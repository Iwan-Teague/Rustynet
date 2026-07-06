#![allow(dead_code)]
use std::fmt;
use std::path::{Path, PathBuf};

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::error::AdapterError;

// Manual Debug to redact `ssh_password`.
impl fmt::Debug for NodeConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeConnection::Ssh {
                host,
                port,
                user,
                identity_file,
                known_hosts,
                ssh_password: _,
            } => f
                .debug_struct("Ssh")
                .field("host", host)
                .field("port", port)
                .field("user", user)
                .field("identity_file", identity_file)
                .field("known_hosts", known_hosts)
                .field("ssh_password", &"<redacted>")
                .finish(),
            NodeConnection::Adb { device_serial } => f
                .debug_struct("Adb")
                .field("device_serial", device_serial)
                .finish(),
            NodeConnection::Mdm { enrollment_id } => f
                .debug_struct("Mdm")
                .field("enrollment_id", enrollment_id)
                .finish(),
        }
    }
}

/// Transport injected at adapter construction by `node_adapter_for`.
/// `NodeAdapter` methods carry no connection argument — connection details
/// live here, not on every call site.
#[derive(Clone)]
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
        /// SSH-password fallback for lab VMs that don't have
        /// passwordless-sudo pre-configured. Only used by
        /// `prime_remote_access` to push a temporary sudoers grant
        /// before cleanup/bootstap; never used for general SSH.
        /// Redacted in Debug.
        ssh_password: Option<String>,
    },
    /// Android Debug Bridge — lab-only, not a production path.
    Adb { device_serial: String },
    /// Apple MDM / Network Extension management channel — future `IosNodeAdapter`.
    Mdm { enrollment_id: String },
}

impl NodeConnection {
    /// Build an SSH connection. Returns `Err` if `known_hosts` does not exist.
    /// `StrictHostKeyChecking=yes` depends on this file being present + correct.
    /// `ssh_password` is the optional lab-VM SSH password used only by
    /// `prime_remote_access` to push a temporary sudoers grant; never used
    /// for general SSH operations (which use the identity file).
    pub fn ssh(
        host: impl Into<String>,
        port: u16,
        user: Option<String>,
        identity_file: PathBuf,
        known_hosts: PathBuf,
        ssh_password: Option<String>,
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
            ssh_password,
        })
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            NodeConnection::Ssh { .. } => "ssh",
            NodeConnection::Adb { .. } => "adb",
            NodeConnection::Mdm { .. } => "mdm",
        }
    }

    /// Full SSH connection parameters including known_hosts, for stages that
    /// dispatch standalone e2e validation binaries.
    pub fn ssh_connection_params(
        &self,
    ) -> Option<super::adapter::node_adapter::SshConnectionParams> {
        match self {
            NodeConnection::Ssh {
                host,
                port,
                user,
                identity_file,
                known_hosts,
                ..
            } => Some(super::adapter::node_adapter::SshConnectionParams::new(
                host.clone(),
                *port,
                user.clone(),
                identity_file.clone(),
                known_hosts.clone(),
            )),
            _ => None,
        }
    }

    /// SSH host+user+port for `sshpass`-based commands. `(host, port, user, identity_file, password)`.
    #[allow(clippy::type_complexity)]
    pub fn ssh_parts(&self) -> Option<(&str, u16, Option<&str>, &Path, Option<&str>)> {
        match self {
            NodeConnection::Ssh {
                host,
                port,
                user,
                identity_file,
                ssh_password,
                ..
            } => Some((
                host,
                *port,
                user.as_deref(),
                identity_file,
                ssh_password.as_deref(),
            )),
            _ => None,
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
            None,
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
            None,
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
            None,
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
