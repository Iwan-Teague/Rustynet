//! macOS utun fd-passing helper — client side.
//!
//! Sends a compact RNUF request frame to the privileged helper over a Unix-domain
//! socket, and receives the open utun file descriptor back via `SCM_RIGHTS`
//! ancillary data.  This module is compiled only on macOS.
//!
//! # Frame format
//!
//! ```text
//! [RNUF magic: 4 bytes][version: 1 byte][name_len: 1 byte][name bytes: name_len]
//! ```
//!
//! This is a distinct sub-protocol from the existing RNHF frame so that the
//! privileged-helper accept loop can dispatch on the first four bytes.
//!
//! This file is `#![forbid(unsafe_code)]`. All unsafe code lives in the companion
//! module `macos_utun_helper_unsafe`.

#![forbid(unsafe_code)]

use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

/// The 4-byte magic prefix for RNUF (Rustynet Utun Frame) connections.
pub(crate) const RNUF_MAGIC: [u8; 4] = *b"RNUF";
/// Protocol version embedded in every RNUF frame.
pub(crate) const RNUF_VERSION: u8 = 1;

/// Maximum accepted interface name length (e.g. `utun9999` = 8 chars; hard cap at 15).
const MAX_IFACE_NAME_LEN: usize = 15;

/// Validate that `interface_name` is safe to send to the privileged helper.
///
/// Rejects:
/// - empty names
/// - names not starting with `utun`
/// - names where the suffix is not all-ASCII digits
/// - names longer than [`MAX_IFACE_NAME_LEN`]
/// - any non-ASCII-alphanumeric characters (defence against CWE-78 injection)
pub fn validate_utun_interface_name(interface_name: &str) -> Result<(), String> {
    if interface_name.is_empty() {
        return Err("interface name must not be empty".to_owned());
    }
    if interface_name.len() > MAX_IFACE_NAME_LEN {
        return Err(format!(
            "interface name '{}' exceeds max length {}",
            interface_name, MAX_IFACE_NAME_LEN
        ));
    }
    let suffix = interface_name
        .strip_prefix("utun")
        .ok_or_else(|| format!("interface name '{}' must start with 'utun'", interface_name))?;
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "interface name '{}' must be 'utun' followed by one or more digits",
            interface_name
        ));
    }
    Ok(())
}

/// Send an RNUF open-utun request to the privileged helper and return the open fd.
///
/// Connects to `socket_path`, writes the RNUF frame, and receives the utun
/// `OwnedFd` via `SCM_RIGHTS`.  Returns `Err` on any protocol or I/O failure.
pub fn send_utun_open_request(
    socket_path: &Path,
    interface_name: &str,
    timeout: Duration,
) -> Result<OwnedFd, String> {
    validate_utun_interface_name(interface_name)?;
    crate::macos_utun_helper_unsafe::send_rnuf_and_recv_fd(socket_path, interface_name, timeout)
}

#[cfg(test)]
mod tests {
    use super::validate_utun_interface_name;

    #[test]
    fn utun_name_validation_rejects_injection_vectors() {
        assert!(validate_utun_interface_name("utun-evil").is_err());
        assert!(validate_utun_interface_name("utun;rm -rf /").is_err());
        assert!(validate_utun_interface_name("").is_err());
        assert!(validate_utun_interface_name("utun").is_err());
        assert!(validate_utun_interface_name("utunX").is_err());
        assert!(validate_utun_interface_name("utun 0").is_err());
        assert!(validate_utun_interface_name("utun0\n").is_err());
        assert!(validate_utun_interface_name("utun123456789012").is_err());
        assert!(validate_utun_interface_name("tun0").is_err());
        assert!(validate_utun_interface_name("rustynet0").is_err());
    }

    #[test]
    fn utun_name_validation_accepts_numbered_names() {
        assert!(validate_utun_interface_name("utun0").is_ok());
        assert!(validate_utun_interface_name("utun9").is_ok());
        assert!(validate_utun_interface_name("utun10").is_ok());
        assert!(validate_utun_interface_name("utun999").is_ok());
    }
}
