#![allow(dead_code)]
use std::path::PathBuf;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::error::AdapterError;

/// Transport injected at adapter construction by `node_adapter_for`.
/// `NodeAdapter` methods carry no connection argument — connection details
/// live here, not on every call site.
#[derive(Debug, Clone)]
pub enum NodeConnection {
    /// SSH to a POSIX or PowerShell-capable host (Linux, Windows, macOS).
    Ssh {
        host: String,
        port: u16,
        user: Option<String>,
        identity_file: PathBuf,
        /// `StrictHostKeyChecking=yes` enforced at SSH layer.
        /// Path is validated to exist at construction time.
        known_hosts: PathBuf,
    },
    /// Android Debug Bridge — lab-only, not a production path.
    Adb { device_serial: String },
    /// Apple MDM / Network Extension management channel — future IosNodeAdapter.
    Mdm { enrollment_id: String },
}

impl NodeConnection {
    /// Build an SSH connection. Returns `Err` if `known_hosts` does not exist.
    /// `StrictHostKeyChecking=yes` depends on this file being present + correct.
    pub fn ssh(
        host: impl Into<String>,
        port: u16,
        user: Option<String>,
        identity_file: PathBuf,
        known_hosts: PathBuf,
    ) -> Result<Self, AdapterError> {
        if !known_hosts.exists() {
            return Err(AdapterError::InvalidPath {
                path: known_hosts,
                reason: "known_hosts file does not exist; \
                         StrictHostKeyChecking=yes requires this file \
                         to be pre-populated before connecting"
                    .to_owned(),
            });
        }
        Ok(NodeConnection::Ssh {
            host: host.into(),
            port,
            user,
            identity_file,
            known_hosts,
        })
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            NodeConnection::Ssh { .. } => "ssh",
            NodeConnection::Adb { .. } => "adb",
            NodeConnection::Mdm { .. } => "mdm",
        }
    }

    /// Returns true if this connection type is valid for the given platform.
    pub fn is_valid_for_platform(&self, platform: &VmGuestPlatform) -> bool {
        matches!(
            (self, platform),
            (NodeConnection::Ssh { .. }, VmGuestPlatform::Linux)
                | (NodeConnection::Ssh { .. }, VmGuestPlatform::Windows)
                | (NodeConnection::Ssh { .. }, VmGuestPlatform::Macos)
                | (NodeConnection::Adb { .. }, VmGuestPlatform::Android)
                | (NodeConnection::Mdm { .. }, VmGuestPlatform::Ios)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn ssh_construction_rejects_absent_known_hosts() {
        let absent = PathBuf::from("/nonexistent/known_hosts_x9z7");
        let result = NodeConnection::ssh(
            "10.0.0.1",
            22,
            None,
            PathBuf::from("/id_rsa"),
            absent.clone(),
        );
        assert!(result.is_err(), "must reject absent known_hosts");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("known_hosts"),
            "error mentions known_hosts: {err}"
        );
    }

    #[test]
    fn ssh_construction_accepts_existing_known_hosts() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# placeholder").unwrap();
        let result = NodeConnection::ssh(
            "10.0.0.1",
            22,
            None,
            PathBuf::from("/id_rsa"),
            f.path().to_path_buf(),
        );
        assert!(
            result.is_ok(),
            "must accept existing known_hosts: {result:?}"
        );
    }

    #[test]
    fn connection_platform_validation() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# placeholder").unwrap();
        let ssh = NodeConnection::ssh(
            "10.0.0.1",
            22,
            None,
            PathBuf::from("/id"),
            f.path().to_path_buf(),
        )
        .unwrap();
        let adb = NodeConnection::Adb {
            device_serial: "serial123".to_owned(),
        };

        assert!(ssh.is_valid_for_platform(&VmGuestPlatform::Linux));
        assert!(ssh.is_valid_for_platform(&VmGuestPlatform::Windows));
        assert!(ssh.is_valid_for_platform(&VmGuestPlatform::Macos));
        assert!(!ssh.is_valid_for_platform(&VmGuestPlatform::Ios));
        assert!(!ssh.is_valid_for_platform(&VmGuestPlatform::Android));
        assert!(adb.is_valid_for_platform(&VmGuestPlatform::Android));
        assert!(!adb.is_valid_for_platform(&VmGuestPlatform::Linux));
    }
}
