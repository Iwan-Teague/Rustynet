#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::linux::LinuxNodeAdapter;
use crate::vm_lab::orchestrator::adapter::macos::MacosNodeAdapter;
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::adapter::windows::WindowsNodeAdapter;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::AdapterError;

const IOS_UNSUPPORTED_MSG: &str = "\
iOS node adapter is not yet implemented. Blocked by security minimum bar: \
(1) no daemon validator coverage — service-hardening-check, key-custody-check, \
dns-failclosed-check not implemented for iOS; \
(2) no reviewed key custody model — Secure Enclave / Keychain integration not designed; \
(3) MDM/Network Extension connection model not reviewed against security minimum bar.";

const ANDROID_UNSUPPORTED_MSG: &str = "\
Android node adapter is not yet implemented. Blocked by security minimum bar: \
(1) no daemon validator coverage — service-hardening-check, key-custody-check, \
dns-failclosed-check not implemented for Android; \
(2) no reviewed key custody model — Android Keystore / StrongBox integration not designed; \
(3) ADB connection model is a lab-only escape hatch — production Android requires \
an app-layer management channel reviewed against security minimum bar.";

/// Build a `NodeAdapter` for the given platform using `conn` as its transport.
/// `alias` must match the `NodeRoleAssignment::alias` for this node.
/// `remote_workdir` is the path to the RustyNet source tree on the remote host;
/// required for Windows `install_daemon`, populated from inventory `rustynet_src_dir`.
///
/// Error precedence:
/// 1. `ConnectionPlatformMismatch` if connection type is wrong for platform
///    (e.g. `Adb` + Linux, `Ssh` + iOS).
/// 2. `UnsupportedPlatform` if platform is not yet implemented (iOS, Android)
///    with a valid connection type — blocked by security minimum bar.
pub fn node_adapter_for(
    alias: impl Into<String>,
    platform: VmGuestPlatform,
    conn: NodeConnection,
    remote_workdir: Option<String>,
) -> Result<Box<dyn NodeAdapter>, AdapterError> {
    let alias = alias.into();
    // Connection-type check comes first so Ssh+iOS → ConnectionPlatformMismatch,
    // while Mdm+iOS → UnsupportedPlatform.
    if !conn.is_valid_for_platform(&platform) {
        return Err(AdapterError::ConnectionPlatformMismatch {
            platform,
            connection_kind: conn.kind_label(),
        });
    }

    match platform {
        VmGuestPlatform::Linux => Ok(Box::new(LinuxNodeAdapter::new(alias, conn))),
        VmGuestPlatform::Windows => Ok(Box::new(WindowsNodeAdapter::new(
            alias,
            conn,
            remote_workdir,
        ))),
        VmGuestPlatform::Macos => Ok(Box::new(MacosNodeAdapter::new(alias, conn, remote_workdir))),
        VmGuestPlatform::Ios => Err(AdapterError::UnsupportedPlatform {
            platform,
            message: IOS_UNSUPPORTED_MSG.to_owned(),
        }),
        VmGuestPlatform::Android => Err(AdapterError::UnsupportedPlatform {
            platform,
            message: ANDROID_UNSUPPORTED_MSG.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn make_ssh_conn_with_file(f: &NamedTempFile) -> NodeConnection {
        NodeConnection::ssh(
            "10.0.0.1",
            22,
            None,
            PathBuf::from("/id_rsa"),
            f.path().to_path_buf(),
        )
        .unwrap()
    }

    #[test]
    fn factory_linux_returns_linux_adapter() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# kh").unwrap();
        let adapter = node_adapter_for(
            "exit",
            VmGuestPlatform::Linux,
            make_ssh_conn_with_file(&f),
            None,
        )
        .unwrap();
        assert_eq!(adapter.platform(), VmGuestPlatform::Linux);
        assert_eq!(adapter.alias(), "exit");
    }

    #[test]
    fn factory_windows_returns_windows_adapter() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# kh").unwrap();
        let adapter = node_adapter_for(
            "win-node",
            VmGuestPlatform::Windows,
            make_ssh_conn_with_file(&f),
            None,
        )
        .unwrap();
        assert_eq!(adapter.platform(), VmGuestPlatform::Windows);
        assert_eq!(adapter.alias(), "win-node");
    }

    #[test]
    fn factory_macos_returns_macos_adapter() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# kh").unwrap();
        let adapter = node_adapter_for(
            "mac-node",
            VmGuestPlatform::Macos,
            make_ssh_conn_with_file(&f),
            None,
        )
        .unwrap();
        assert_eq!(adapter.platform(), VmGuestPlatform::Macos);
    }

    #[test]
    fn factory_ios_returns_unsupported_error_with_security_message() {
        let conn = NodeConnection::Mdm {
            enrollment_id: "enroll-123".to_owned(),
        };
        let err = node_adapter_for("ios-node", VmGuestPlatform::Ios, conn, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("security minimum bar"),
            "iOS error must mention 'security minimum bar': {msg}"
        );
        assert!(
            matches!(err, AdapterError::UnsupportedPlatform { .. }),
            "expected UnsupportedPlatform, got: {err:?}"
        );
    }

    #[test]
    fn factory_android_returns_unsupported_error_with_security_message() {
        let conn = NodeConnection::Adb {
            device_serial: "abc123".to_owned(),
        };
        let err =
            node_adapter_for("android-node", VmGuestPlatform::Android, conn, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("security minimum bar"),
            "Android error must mention 'security minimum bar': {msg}"
        );
        assert!(
            matches!(err, AdapterError::UnsupportedPlatform { .. }),
            "expected UnsupportedPlatform, got: {err:?}"
        );
    }

    #[test]
    fn factory_rejects_adb_for_linux() {
        let conn = NodeConnection::Adb {
            device_serial: "abc123".to_owned(),
        };
        let err = node_adapter_for("node", VmGuestPlatform::Linux, conn, None).unwrap_err();
        assert!(
            matches!(err, AdapterError::ConnectionPlatformMismatch { .. }),
            "expected ConnectionPlatformMismatch, got: {err:?}"
        );
    }

    #[test]
    fn factory_rejects_ssh_for_ios() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# kh").unwrap();
        let conn = make_ssh_conn_with_file(&f);
        let err = node_adapter_for("node", VmGuestPlatform::Ios, conn, None).unwrap_err();
        assert!(
            matches!(err, AdapterError::ConnectionPlatformMismatch { .. }),
            "expected ConnectionPlatformMismatch, got: {err:?}"
        );
    }
}
