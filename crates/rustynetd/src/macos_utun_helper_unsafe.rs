//! Unsafe companion for `macos_utun_helper` — SCM_RIGHTS fd-passing on macOS.
//!
//! All `unsafe` code in the utun helper is isolated here so that the safe
//! client module (`macos_utun_helper`) and the safe server module
//! (`macos_utun_helper_server`) can remain `#![forbid(unsafe_code)]`.
//!
//! External callers use only:
//! - [`send_rnuf_and_recv_fd`] — client: connect, send RNUF frame, recv fd
//! - [`open_utun_and_send_fd`] — server: open utun device, send fd via SCM_RIGHTS
//! - [`send_error_response`]   — server: send 1-byte error status + message
//! - [`peek_first_4_bytes`]    — server accept loop: dispatch RNUF vs RNHF
//!
//! ## Protocol contract (RNUF)
//!
//! Client side ([`send_rnuf_and_recv_fd`]):
//! 1. Connect to the helper's Unix socket.
//! 2. Write the RNUF frame (magic + version + name_len + name).
//! 3. Half-close the write side (`shutdown(Shutdown::Write)`). This signals
//!    EOF to the helper's trailing-byte intrusion check, which would
//!    otherwise block waiting on the helper's read-timeout — see Gap I
//!    (commit `b565810`) for the pre-fix deadlock.
//! 4. `recvmsg` for a single fd plus an optional inline error payload.
//!    If the first byte of received data is `0xFF`, the helper failed to
//!    open the device and the trailing bytes carry the UTF-8 error text.
//!    Surface that text as `Err` so the daemon logs the root cause
//!    instead of timing out silently.
//!
//! Helper side ([`open_utun_and_send_fd`] / [`send_error_response`]):
//! - On success: `sendmsg` the open utun fd via SCM_RIGHTS with a single
//!   0x00 data byte (`MSG_CTRUNC` on the receiver would discard the fd, so
//!   we always send a one-byte iovec to keep the contract clear).
//! - On failure: write `[0xFF, error_message_bytes...]` and return Err.

use std::io;
use std::net::Shutdown;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::macos_utun_helper::{RNUF_MAGIC, RNUF_VERSION};

/// Maximum length, in bytes, of an inline RNUF error response (after the
/// 0xFF marker). Bounded so we never allocate unbounded buffers when a
/// peer streams garbage in place of an error message.
const RNUF_MAX_ERROR_BYTES: usize = 4096;

/// Client: connect to `socket_path`, send RNUF frame, receive open utun `OwnedFd`.
pub(crate) fn send_rnuf_and_recv_fd(
    socket_path: &Path,
    interface_name: &str,
    timeout: Duration,
) -> Result<OwnedFd, String> {
    let stream =
        UnixStream::connect(socket_path).map_err(|e| format!("utun helper connect failed: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("utun helper set_read_timeout failed: {e}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("utun helper set_write_timeout failed: {e}"))?;

    // Build RNUF frame
    let name_bytes = interface_name.as_bytes();
    let name_len = u8::try_from(name_bytes.len())
        .map_err(|_| "interface name too long for RNUF frame".to_owned())?;
    let mut frame = Vec::with_capacity(RNUF_MAGIC.len() + 2 + name_bytes.len());
    frame.extend_from_slice(&RNUF_MAGIC);
    frame.push(RNUF_VERSION);
    frame.push(name_len);
    frame.extend_from_slice(name_bytes);

    {
        use std::io::Write as _;
        let mut s = &stream;
        s.write_all(&frame)
            .map_err(|e| format!("utun helper write RNUF frame failed: {e}"))?;
    }

    // Half-close write side: the helper's protocol check reads one extra
    // byte to detect injected trailing payload. Without an explicit EOF
    // from us, that read blocks for the helper's full I/O timeout (30s),
    // which races our recvmsg timeout and produces a silent EAGAIN.
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("utun helper shutdown(write) failed: {e}"))?;

    recv_fd_from_stream(&stream)
}

fn recv_fd_from_stream(stream: &UnixStream) -> Result<OwnedFd, String> {
    use std::os::fd::AsRawFd;
    // Inline error payload: 0xFF marker + up to RNUF_MAX_ERROR_BYTES text.
    let mut data_buf = vec![0u8; 1 + RNUF_MAX_ERROR_BYTES];
    // CMSG_SPACE for one fd: libc::CMSG_SPACE(size_of::<RawFd>()) = 16 on macOS
    let cmsg_buf_size = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_buf_size];

    let sock_fd = stream.as_raw_fd();
    let RecvOutcome {
        bytes,
        fd: fd_opt,
        msg_flags,
        msg_controllen,
    } = recvmsg_one_fd(sock_fd, &mut data_buf, &mut cmsg_buf)?;

    // MSG_CTRUNC means the kernel truncated ancillary data — the fd would
    // have been silently dropped. Fail closed rather than fall through.
    if msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(format!(
            "utun helper: recvmsg returned MSG_CTRUNC (cmsg buffer too small, msg_controllen={msg_controllen}, bytes={bytes})"
        ));
    }

    // Inline error reply from helper: first byte is 0xFF, rest is UTF-8 text.
    if bytes > 0 && data_buf[0] == 0xFF {
        let mut error_text = String::new();
        if bytes > 1 {
            let payload = &data_buf[1..bytes];
            error_text.push_str(&String::from_utf8_lossy(payload));
        }
        // Drain any trailing bytes the helper streamed after the first recvmsg
        // returned. macOS sometimes splits a small data+message reply across
        // multiple readable chunks; collecting up to RNUF_MAX_ERROR_BYTES total
        // keeps the message intact without unbounded read.
        let remaining = RNUF_MAX_ERROR_BYTES.saturating_sub(error_text.len());
        if remaining > 0 {
            let mut extra = vec![0u8; remaining];
            use std::io::Read as _;
            let mut s = stream;
            loop {
                match s.read(&mut extra) {
                    Ok(0) => break,
                    Ok(n) => {
                        error_text.push_str(&String::from_utf8_lossy(&extra[..n]));
                        if error_text.len() >= RNUF_MAX_ERROR_BYTES {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        let trimmed = error_text.trim_end_matches(char::from(0));
        return Err(format!(
            "utun helper reported failure: {}",
            if trimmed.is_empty() {
                "<no error message>"
            } else {
                trimmed
            }
        ));
    }

    fd_opt.ok_or_else(|| {
        format!(
            "utun helper: no fd received from privileged helper (bytes={bytes}, msg_controllen={msg_controllen})"
        )
    })
}

struct RecvOutcome {
    bytes: usize,
    fd: Option<OwnedFd>,
    msg_flags: libc::c_int,
    msg_controllen: libc::socklen_t,
}

fn recvmsg_one_fd(
    sock_fd: RawFd,
    data_buf: &mut [u8],
    cmsg_buf: &mut [u8],
) -> Result<RecvOutcome, String> {
    let mut iov = libc::iovec {
        iov_base: data_buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: data_buf.len(),
    };
    let mut msghdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: cmsg_buf.len() as libc::socklen_t,
        msg_flags: 0,
    };

    let nbytes = unsafe { libc::recvmsg(sock_fd, &mut msghdr, 0) };
    if nbytes < 0 {
        return Err(format!(
            "utun helper recvmsg failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Walk ancillary data looking for SCM_RIGHTS
    let mut fd_opt: Option<OwnedFd> = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msghdr);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                let raw_fd = std::ptr::read_unaligned(data_ptr);
                if raw_fd >= 0 {
                    fd_opt = Some(OwnedFd::from_raw_fd(raw_fd));
                }
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msghdr, cmsg);
        }
    }

    Ok(RecvOutcome {
        bytes: nbytes as usize,
        fd: fd_opt,
        msg_flags: msghdr.msg_flags,
        msg_controllen: msghdr.msg_controllen,
    })
}

/// Server: open `interface_name` as a utun device and send the fd via SCM_RIGHTS.
pub(crate) fn open_utun_and_send_fd(
    stream: &UnixStream,
    interface_name: &str,
) -> Result<(), String> {
    use std::os::fd::IntoRawFd;

    let device = rustynet_tun::SyncDevice::open(interface_name)
        .map_err(|e| format!("utun helper SyncDevice::open({interface_name}) failed: {e}"))?;
    let raw_fd = device.into_raw_fd();
    let send_result = sendmsg_fd(stream, raw_fd);
    // SCM_RIGHTS dup'd the fd into the peer process. Our local fd is now
    // surplus; closing it does NOT invalidate the dup the peer holds.
    // Always run the close, even on send failure, to avoid an fd leak.
    let close_result = unsafe { libc::close(raw_fd) };
    if close_result < 0 {
        // Surface the close failure if the sendmsg itself succeeded —
        // otherwise the sendmsg error wins (it's strictly more useful).
        let close_err = std::io::Error::last_os_error();
        if send_result.is_ok() {
            return Err(format!("utun helper close({raw_fd}) failed: {close_err}"));
        }
    }
    send_result
}

fn sendmsg_fd(stream: &UnixStream, fd: RawFd) -> Result<(), String> {
    use std::os::fd::AsRawFd;

    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    // macOS requires a non-empty iovec for SCM_RIGHTS to be transferred —
    // sendmsg with iov_len=0 succeeds but silently drops the ancillary
    // payload. A single 0x00 byte is the conventional handshake byte that
    // also distinguishes the success path (data_buf[0] == 0x00) from the
    // failure path (data_buf[0] == 0xFF) on the receiver.
    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut dummy) as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    let msghdr = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: cmsg_space as libc::socklen_t,
        msg_flags: 0,
    };

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msghdr);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as libc::socklen_t;
        let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
        std::ptr::write_unaligned(data, fd);

        let result = libc::sendmsg(stream.as_raw_fd(), &msghdr, 0);
        if result < 0 {
            return Err(format!(
                "utun helper sendmsg failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

/// Peek the first 4 bytes of a Unix stream without consuming them.
///
/// Uses `libc::recv` with `MSG_PEEK` because `UnixStream::peek` is unstable
/// (`unix_socket_peek`). Returns the number of bytes peeked (0 if peer closed
/// before sending 4 bytes). Used by the privileged-helper accept loop to
/// dispatch RNUF (macOS utun fd-passing) vs RNHF (general command) frames
/// without disturbing the byte stream that the downstream handler will read.
pub(crate) fn peek_first_4_bytes(stream: &UnixStream) -> io::Result<[u8; 4]> {
    use std::os::fd::AsRawFd;
    let mut buf = [0u8; 4];
    let nbytes = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
            libc::MSG_PEEK,
        )
    };
    if nbytes < 0 {
        return Err(io::Error::last_os_error());
    }
    if (nbytes as usize) < buf.len() {
        // Pad with zeros if fewer than 4 bytes were peekable — caller checks
        // against known 4-byte magics, so partial peek will never match.
        for byte in &mut buf[nbytes as usize..] {
            *byte = 0;
        }
    }
    Ok(buf)
}

/// Server: send a 1-byte error indicator followed by the error message text.
///
/// Best-effort: ignores write failures (caller is about to return Err anyway).
/// Wire format is `[0xFF, error_message_bytes...]` capped at
/// [`RNUF_MAX_ERROR_BYTES`] so a runaway helper cannot stream unbounded data.
pub(crate) fn send_error_response(stream: &mut UnixStream, message: &str) {
    use std::io::Write;
    let _ = stream.write_all(&[0xFF]);
    let bytes = message.as_bytes();
    let len = bytes.len().min(RNUF_MAX_ERROR_BYTES);
    let _ = stream.write_all(&bytes[..len]);
    let _ = stream.flush();
}

/// Test-only: send an open fd via SCM_RIGHTS using the same `sendmsg`
/// machinery as the helper. Lets unit tests exercise the receive path
/// without opening a real utun device.
#[cfg(test)]
pub(crate) fn test_send_fd(stream: &UnixStream, fd: RawFd) -> Result<(), String> {
    sendmsg_fd(stream, fd)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::Duration;

    use super::{recv_fd_from_stream, send_error_response, sendmsg_fd, test_send_fd};

    #[test]
    fn send_rnuf_frame_roundtrip_data() {
        // Only tests that the RNUF frame bytes are structurally correct
        use crate::macos_utun_helper::{RNUF_MAGIC, RNUF_VERSION};
        let name = "utun9";
        let name_bytes = name.as_bytes();
        let mut frame = Vec::new();
        frame.extend_from_slice(&RNUF_MAGIC);
        frame.push(RNUF_VERSION);
        frame.push(name_bytes.len() as u8);
        frame.extend_from_slice(name_bytes);
        assert_eq!(&frame[..4], b"RNUF");
        assert_eq!(frame[4], 1);
        assert_eq!(frame[5] as usize, name.len());
        assert_eq!(&frame[6..], name.as_bytes());
    }

    #[test]
    fn send_error_response_does_not_panic() {
        let (mut client, _server) = UnixStream::pair().unwrap();
        send_error_response(&mut client, "test error");
    }

    /// Happy-path: server-side `sendmsg_fd` transfers a real fd that
    /// `recv_fd_from_stream` reconstructs into an `OwnedFd`. Uses a
    /// throwaway pipe fd as the "device" since we can't open utun in
    /// userspace tests.
    #[test]
    fn recv_fd_succeeds_when_helper_sends_scm_rights() {
        let (client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Open a pipe fd to pass through SCM_RIGHTS — any kernel-managed
        // fd is acceptable as the test payload (we just verify the
        // transfer mechanics work, not what kind of fd it is).
        let mut pipe_fds = [0i32; 2];
        let rc = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe() failed");
        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];

        let server_thread = thread::spawn(move || {
            test_send_fd(&server, read_fd).expect("sendmsg_fd must succeed");
            // Close our local copy of the fd (peer now owns a dup).
            unsafe { libc::close(read_fd) };
            drop(server);
        });

        let received = recv_fd_from_stream(&client).expect("recv_fd must succeed");
        // Sanity: writing into the pipe (write_fd is still ours) should
        // be readable through the dup'd fd we just received.
        let payload = b"hello-utun";
        let n = unsafe {
            libc::write(
                write_fd,
                payload.as_ptr().cast::<libc::c_void>(),
                payload.len(),
            )
        };
        assert_eq!(n, payload.len() as isize);
        unsafe { libc::close(write_fd) };

        let mut buf = [0u8; 32];
        let n = unsafe {
            libc::read(
                received.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        assert!(n > 0, "received fd must be readable");
        assert_eq!(&buf[..n as usize], payload);

        server_thread.join().unwrap();
    }

    /// Error-marker path: server writes `[0xFF, message...]`, client
    /// surfaces the message text in the returned error.
    #[test]
    fn recv_fd_surfaces_helper_error_reply() {
        let (client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let server_thread = thread::spawn(move || {
            send_error_response(&mut server, "SyncDevice::open(utun9) failed: EPERM");
            // Close write side so client's drain loop terminates promptly.
            let _ = server.shutdown(Shutdown::Write);
            drop(server);
        });

        let err = recv_fd_from_stream(&client).expect_err("must surface error");
        assert!(
            err.contains("SyncDevice::open(utun9) failed: EPERM"),
            "expected error to embed helper's message, got: {err}"
        );
        assert!(
            err.contains("utun helper reported failure"),
            "expected error prefix, got: {err}"
        );

        server_thread.join().unwrap();
    }

    /// Truncated-control scenario: server sends a real fd via SCM_RIGHTS
    /// but the receiver's cmsg buffer is sized to zero. Some kernels set
    /// MSG_CTRUNC here; current macOS may instead return the data byte
    /// and drop ancillary data without the flag. Either way the security
    /// invariant is the same: never reconstruct an fd from truncated or
    /// missing control data.
    #[test]
    fn recvmsg_with_too_small_cmsg_never_reconstructs_fd() {
        use super::recvmsg_one_fd;
        let (client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut pipe_fds = [0i32; 2];
        let rc = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];

        let server_thread = thread::spawn(move || {
            test_send_fd(&server, read_fd).expect("sendmsg_fd must succeed");
            unsafe { libc::close(read_fd) };
            unsafe { libc::close(write_fd) };
            drop(server);
        });

        // Empty cmsg buffer: kernel may set MSG_CTRUNC, or may return no
        // ancillary entries. In both cases no fd may be reconstructed.
        let mut data_buf = [0u8; 8];
        let mut empty_cmsg: [u8; 0] = [];
        let outcome = recvmsg_one_fd(client.as_raw_fd(), &mut data_buf, &mut empty_cmsg)
            .expect("recvmsg itself must not error");
        assert!(
            outcome.fd.is_none(),
            "fd must not be reconstructed when cmsg was truncated or absent"
        );

        server_thread.join().unwrap();
    }

    /// Half-close-write contract: after the client writes the RNUF frame
    /// and calls shutdown(Write), a `read()` on the server side returns
    /// Ok(0) immediately. This is the property that fixes the trailing-byte
    /// deadlock in `handle_utun_open_request`.
    #[test]
    fn shutdown_write_unblocks_helper_trailing_read() {
        use std::io::Read;
        let (client, mut server) = UnixStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let writer_thread = thread::spawn(move || {
            let mut c = &client;
            c.write_all(b"RNUF\x01\x05utun9").unwrap();
            // Client's contract: half-close write so helper's trailing
            // read sees EOF instead of timing out.
            client.shutdown(Shutdown::Write).unwrap();
            drop(client);
        });

        let mut header = [0u8; 6];
        server.read_exact(&mut header).unwrap();
        let mut name = [0u8; 5];
        server.read_exact(&mut name).unwrap();
        // The critical read: with shutdown(Write), this is Ok(0), NOT a
        // 2s timeout error. Pre-fix this used to block for io_timeout.
        let mut trailing = [0u8; 1];
        let n = server.read(&mut trailing).unwrap();
        assert_eq!(
            n, 0,
            "trailing read must hit EOF immediately after shutdown"
        );

        writer_thread.join().unwrap();
    }

    /// Sanity: a bare sendmsg (no shutdown call on client) does NOT close
    /// the local fd as a side-effect — close + sendmsg ordering only
    /// matters if we close BEFORE sendmsg.
    #[test]
    fn sendmsg_then_close_does_not_invalidate_peer_fd() {
        let (client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut pipe_fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];

        sendmsg_fd(&server, read_fd).expect("sendmsg must succeed");
        // Close local copy AFTER sendmsg: kernel already dup'd into peer.
        unsafe { libc::close(read_fd) };

        // Write into the pipe; the peer's dup of read_fd should still
        // see the data.
        let payload = b"x";
        assert_eq!(
            unsafe {
                libc::write(
                    write_fd,
                    payload.as_ptr().cast::<libc::c_void>(),
                    payload.len(),
                )
            },
            1
        );
        unsafe { libc::close(write_fd) };

        let received = recv_fd_from_stream(&client).expect("recv_fd succeeds");
        let mut buf = [0u8; 4];
        let n = unsafe {
            libc::read(
                received.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        assert!(
            n > 0,
            "peer's dup fd must still be readable after local close"
        );
    }
}
