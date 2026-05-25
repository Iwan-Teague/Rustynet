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

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::macos_utun_helper::{RNUF_MAGIC, RNUF_VERSION};

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

    recv_fd_from_stream(&stream)
}

fn recv_fd_from_stream(stream: &UnixStream) -> Result<OwnedFd, String> {
    use std::os::fd::AsRawFd;
    // We need space for one ancillary fd plus a small data payload.
    let mut data_buf = [0u8; 8];
    // CMSG_SPACE for one fd: libc::CMSG_SPACE(size_of::<RawFd>()) = 16 on macOS
    let cmsg_buf_size = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_buf_size];

    let sock_fd = stream.as_raw_fd();
    let (nbytes, fd_opt) = recvmsg_one_fd(sock_fd, &mut data_buf, &mut cmsg_buf)?;
    let _ = nbytes;

    fd_opt.ok_or_else(|| "utun helper: no fd received from privileged helper".to_owned())
}

fn recvmsg_one_fd(
    sock_fd: RawFd,
    data_buf: &mut [u8],
    cmsg_buf: &mut [u8],
) -> Result<(usize, Option<OwnedFd>), String> {
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

    Ok((nbytes as usize, fd_opt))
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
    let result = sendmsg_fd(stream, raw_fd);
    // Always close: OwnedFd cleanup already fired via into_raw_fd + manual close here.
    unsafe { libc::close(raw_fd) };
    result
}

fn sendmsg_fd(stream: &UnixStream, fd: RawFd) -> Result<(), String> {
    use std::os::fd::AsRawFd;

    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

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
pub(crate) fn send_error_response(stream: &mut UnixStream, message: &str) {
    use std::io::Write;
    let _ = stream.write_all(&[0xFF]);
    let _ = stream.write_all(message.as_bytes());
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use super::send_error_response;

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
}
