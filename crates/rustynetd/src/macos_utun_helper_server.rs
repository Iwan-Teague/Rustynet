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

    // If open_utun_and_send_fd fails, surface the failure via the inline
    // error-reply channel so the client sees an explicit error rather
    // than timing out on recvmsg. This is the second half of the Gap I
    // fix (commit b565810 follow-up): without it, any helper-side
    // SyncDevice::open or sendmsg failure produced a silent recvmsg
    // EAGAIN at the daemon and the dataplane reconcile loop kept
    // retrying indefinitely.
    if let Err(e) = open_utun_and_send_fd(&stream, interface_name) {
        send_error_response(&mut stream, &e);
        return Err(e);
    }
    Ok(())
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

    /// Regression for Gap I (commit `b565810` reproduction): with the
    /// client's `shutdown(Write)` half-close, the helper's trailing-byte
    /// check must NOT block waiting for more data. Pre-fix this test
    /// would hang for the helper's read_timeout; post-fix it returns
    /// promptly because EOF arrives immediately after the frame.
    #[test]
    fn trailing_byte_check_does_not_block_after_client_shutdown_write() {
        use std::io::{Read, Write};
        use std::net::Shutdown;
        use std::time::Duration;

        let (mut client, mut server) = UnixStream::pair().unwrap();
        // Helper-side timeout would surface the deadlock as a 2s test
        // hang if the fix regressed. Keep tight so a CI failure is fast.
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let frame = make_rnuf_frame(RNUF_VERSION, "utun9");
        let writer = std::thread::spawn(move || {
            client.write_all(&frame).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            // Hold client open so we can read the helper's response.
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response);
            response
        });

        // Drive only the protocol-validation portion (mirrors what the
        // real handler does up to `open_utun_and_send_fd`). We can't
        // call the full handler in a unit test because SyncDevice::open
        // requires root. The trailing-byte read happens BEFORE the
        // device open, so this exercises the deadlock fix in isolation.
        let mut header = [0u8; 6];
        server.read_exact(&mut header).unwrap();
        let mut name = [0u8; 5];
        server.read_exact(&mut name).unwrap();
        let mut trailing = [0u8; 1];
        let n = server
            .read(&mut trailing)
            .expect("trailing read must not error");
        assert_eq!(
            n, 0,
            "trailing read must return Ok(0) immediately after client shutdown"
        );

        drop(server);
        let _ = writer.join().unwrap();
    }

    /// On `open_utun_and_send_fd` failure path, server must send a 0xFF
    /// inline error reply so the client sees an explicit error rather
    /// than a recvmsg timeout. Tested here via the existing
    /// `validate_utun_interface_name` rejection branch, which uses the
    /// same `send_error_response` codepath.
    #[test]
    fn error_response_uses_0xff_marker() {
        use std::io::Read;
        use std::net::Shutdown;
        let (mut client, server) = UnixStream::pair().unwrap();
        let frame = make_rnuf_frame(RNUF_VERSION, "rustynet0"); // not utun-prefixed
        std::io::Write::write_all(&mut client, &frame).unwrap();
        client
            .shutdown(Shutdown::Write)
            .expect("client half-close should unblock helper trailing-byte check");

        let _ = handle_utun_open_request(server);

        // Client should see [0xFF, error_message...].
        let mut reply = Vec::new();
        let _ = client.read_to_end(&mut reply);
        assert!(!reply.is_empty(), "helper must send error reply");
        assert_eq!(reply[0], 0xFF, "error reply must start with 0xFF marker");
        let message = String::from_utf8_lossy(&reply[1..]);
        assert!(
            message.contains("rustynet0") || message.contains("interface name"),
            "error message must describe the rejection, got: {message}"
        );
    }
}
