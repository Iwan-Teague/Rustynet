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
///
/// Error precedence:
/// 1. `ConnectionPlatformMismatch` if connection type is wrong for platform
///    (e.g. `Adb` + Linux, `Ssh` + iOS).
/// 2. `UnsupportedPlatform` if platform is not yet implemented (iOS, Android)
///    with a valid connection type — blocked by security minimum bar.
pub fn node_adapter_for(
    platform: VmGuestPlatform,
    conn: NodeConnection,
) -> Result<Box<dyn NodeAdapter>, AdapterError> {
    // Connection-type check comes first so Ssh+iOS → ConnectionPlatformMismatch,
    // while Mdm+iOS → UnsupportedPlatform.
    if !conn.is_valid_for_platform(&platform) {
        return Err(AdapterError::ConnectionPlatformMismatch {
            platform,
            connection_kind: conn.kind_label(),
        });
    }

    match platform {
        VmGuestPlatform::Linux => Ok(Box::new(LinuxNodeAdapter::new(conn))),
        VmGuestPlatform::Windows => Ok(Box::new(WindowsNodeAdapter::new(conn))),
        VmGuestPlatform::Macos => Ok(Box::new(MacosNodeAdapter::new(conn))),
        VmGuestPlatform::Ios => Err(AdapterError::UnsupportedPlatform {
            platform,
            message: IOS_UNSUPPORTED_MSG.to_string(),
        }),
        VmGuestPlatform::Android => Err(AdapterError::UnsupportedPlatform {
            platform,
            message: ANDROID_UNSUPPORTED_MSG.to_string(),
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
        let adapter =
            node_adapter_for(VmGuestPlatform::Linux, make_ssh_conn_with_file(&f)).unwrap();
        assert_eq!(adapter.platform(), VmGuestPlatform::Linux);
    }

    #[test]
    fn factory_windows_returns_windows_adapter() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# kh").unwrap();
        let adapter =
            node_adapter_for(VmGuestPlatform::Windows, make_ssh_conn_with_file(&f)).unwrap();
        assert_eq!(adapter.platform(), VmGuestPlatform::Windows);
    }

    #[test]
    fn factory_macos_returns_macos_adapter() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# kh").unwrap();
        let adapter =
            node_adapter_for(VmGuestPlatform::Macos, make_ssh_conn_with_file(&f)).unwrap();
        assert_eq!(adapter.platform(), VmGuestPlatform::Macos);
    }

    #[test]
    fn factory_ios_returns_unsupported_error_with_security_message() {
        let conn = NodeConnection::Mdm {
            enrollment_id: "enroll-123".to_string(),
        };
        let err = node_adapter_for(VmGuestPlatform::Ios, conn).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("security minimum bar"),
            "iOS error must mention 'security minimum bar': {msg}"
        );
        assert!(
            matches!(err, AdapterError::UnsupportedPlatform { .. }),
            "expected UnsupportedPlatform, got: {:?}",
            err
        );
    }

    #[test]
    fn factory_android_returns_unsupported_error_with_security_message() {
        let conn = NodeConnection::Adb {
            device_serial: "abc123".to_string(),
        };
        let err = node_adapter_for(VmGuestPlatform::Android, conn).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("security minimum bar"),
            "Android error must mention 'security minimum bar': {msg}"
        );
        assert!(
            matches!(err, AdapterError::UnsupportedPlatform { .. }),
            "expected UnsupportedPlatform, got: {:?}",
            err
        );
    }

    #[test]
    fn factory_rejects_adb_for_linux() {
        let conn = NodeConnection::Adb {
            device_serial: "abc123".to_string(),
        };
        let err = node_adapter_for(VmGuestPlatform::Linux, conn).unwrap_err();
        assert!(
            matches!(err, AdapterError::ConnectionPlatformMismatch { .. }),
            "expected ConnectionPlatformMismatch, got: {:?}",
            err
        );
    }

    #[test]
    fn factory_rejects_ssh_for_ios() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# kh").unwrap();
        let conn = make_ssh_conn_with_file(&f);
        let err = node_adapter_for(VmGuestPlatform::Ios, conn).unwrap_err();
        assert!(
            matches!(err, AdapterError::ConnectionPlatformMismatch { .. }),
            "expected ConnectionPlatformMismatch, got: {:?}",
            err
        );
    }
}
