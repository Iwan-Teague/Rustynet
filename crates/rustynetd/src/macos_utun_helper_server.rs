//! macOS utun fd-passing helper — server side.
//!
//! Handles an incoming RNUF connection from the daemon: reads the frame,
//! validates the interface name, calls `SyncDevice::open` as root, and
//! returns the fd via SCM_RIGHTS.
//!
//! This file is `#![forbid(unsafe_code)]`.
//! The unsafe SCM_RIGHTS I/O lives in `macos_utun_helper_unsafe.rs`.

#![forbid(unsafe_code)]

use std::os::unix::net::UnixStream;

use crate::macos_utun_helper::{RNUF_MAGIC, RNUF_VERSION, validate_utun_interface_name};
use crate::macos_utun_helper_unsafe::{open_utun_and_send_fd, send_error_response};

/// Handle a single RNUF connection from the daemon.
///
/// Called by `run_privileged_helper` when it detects the `RNUF` magic bytes.
/// Reads the RNUF frame, validates the interface name, opens the utun device
/// (runs as root), and passes the fd back via `SCM_RIGHTS`.
pub fn handle_utun_open_request(mut stream: UnixStream) -> Result<(), String> {
    // Wire format: [RNUF magic: 4][version: 1][name_len: 1][name_bytes: n]
    let header_len = RNUF_MAGIC.len() + 2; // magic + version + name_len
    let mut header = vec![0u8; header_len];
    use std::io::Read;
    stream
        .read_exact(&mut header)
        .map_err(|e| format!("utun helper failed to read RNUF header: {e}"))?;

    if header[..4] != RNUF_MAGIC {
        return Err("utun helper received invalid RNUF magic".to_owned());
    }
    if header[4] != RNUF_VERSION {
        let msg = format!(
            "utun helper unsupported RNUF version {}; expected {RNUF_VERSION}",
            header[4]
        );
        send_error_response(&mut stream, &msg);
        return Err(msg);
    }

    let name_len = header[5] as usize;
    if name_len == 0 {
        let msg = "utun helper received zero-length interface name".to_owned();
        send_error_response(&mut stream, &msg);
        return Err(msg);
    }

    let mut name_bytes = vec![0u8; name_len];
    stream
        .read_exact(&mut name_bytes)
        .map_err(|e| format!("utun helper failed to read interface name: {e}"))?;

    let interface_name = std::str::from_utf8(&name_bytes)
        .map_err(|e| format!("utun helper received non-UTF-8 interface name: {e}"))?;

    // Reject any trailing bytes after the declared name — protocol error.
    let mut trailing = [0u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) | Err(_) => {} // EOF or error: no trailing bytes, expected
        Ok(_) => {
            let msg = "utun helper received unexpected trailing bytes in RNUF frame".to_owned();
            send_error_response(&mut stream, &msg);
            return Err(msg);
        }
    }

    if let Err(e) = validate_utun_interface_name(interface_name) {
        let msg = format!("utun helper rejected interface name: {e}");
        send_error_response(&mut stream, &msg);
        return Err(msg);
    }

    open_utun_and_send_fd(&stream, interface_name)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    use super::handle_utun_open_request;
    use crate::macos_utun_helper::{RNUF_MAGIC, RNUF_VERSION};

    fn make_rnuf_frame(version: u8, name: &str) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&RNUF_MAGIC);
        frame.push(version);
        frame.push(name.len() as u8);
        frame.extend_from_slice(name.as_bytes());
        frame
    }

    #[test]
    fn rejects_invalid_magic() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let mut bad_frame = Vec::new();
        bad_frame.extend_from_slice(b"BADM");
        bad_frame.extend_from_slice(&[RNUF_VERSION, 5]);
        bad_frame.extend_from_slice(b"utun9");
        client.write_all(&bad_frame).unwrap();
        drop(client);
        let result = handle_utun_open_request(server);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid RNUF magic"));
    }

    #[test]
    fn rejects_unknown_version() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let frame = make_rnuf_frame(99, "utun9");
        client.write_all(&frame).unwrap();
        drop(client);
        let result = handle_utun_open_request(server);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_utun_name() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let frame = make_rnuf_frame(RNUF_VERSION, "rustynet0");
        client.write_all(&frame).unwrap();
        drop(client);
        let result = handle_utun_open_request(server);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_zero_length_name() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&RNUF_MAGIC);
        frame.push(RNUF_VERSION);
        frame.push(0u8); // zero name_len
        client.write_all(&frame).unwrap();
        drop(client);
        let result = handle_utun_open_request(server);
        assert!(result.is_err());
    }
}
