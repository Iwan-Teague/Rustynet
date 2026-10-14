use std::io;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    #[cfg(target_os = "linux")]
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    #[cfg(target_os = "linux")]
    use std::mem;
    use std::os::fd::{AsRawFd, OwnedFd};
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::OpenOptionsExt;

    // Linux only: libc types the ioctl request as `c_ulong` on glibc Linux but as
    // `c_int` on Android (and on musl), and an Android app never opens
    // /dev/net/tun itself (the VPN service hands it an already-configured fd:
    // `from_owned_fd`). The constant therefore stays out of the Android build.
    #[cfg(target_os = "linux")]
    const TUNSETIFF: libc::c_ulong = 0x400454ca;

    pub struct SyncDevice {
        file: File,
    }

    impl SyncDevice {
        /// Adopt an already-configured TUN file descriptor (for example the one an
        /// Android `VpnService` returns from `establish()`), taking ownership: the
        /// descriptor is closed when the `SyncDevice` is dropped. No ioctl is issued
        /// and the interface is not renamed or reconfigured.
        ///
        /// The caller guarantees the descriptor is a TUN device that delivers raw IP
        /// packets without a packet-information header (`IFF_TUN | IFF_NO_PI` on
        /// Linux; Android VPN descriptors are expected to behave the same, which is
        /// UNVERIFIED here and must be proven on a device before relying on it).
        ///
        /// Ownership rules for callers: pass a descriptor Rust may close. On Android
        /// that means a duplicate obtained with `ParcelFileDescriptor.dup()` and then
        /// `detachFd()`; never also `close()` the `ParcelFileDescriptor` that the
        /// descriptor came from, or it is closed twice. The descriptor keeps the
        /// blocking mode it arrives in (an `establish()` fd is typically
        /// non-blocking); call [`SyncDevice::set_nonblocking`] to choose. Unlike
        /// `open`, this does not set `O_CLOEXEC`: an Android app process never execs.
        ///
        /// `recv` returns `Ok(0)` when the descriptor reports end-of-file (closed
        /// peer); callers looping on a blocking descriptor must treat that as the end
        /// and not as an empty packet. `recv` buffers must be at least the tunnel MTU
        /// (`VpnService.Builder.setMtu`, default 1500).
        ///
        /// Returns `io::Result` for API parity with the other platforms (where this is
        /// unsupported); on Linux and Android it cannot fail.
        pub fn from_owned_fd(fd: OwnedFd) -> io::Result<Self> {
            Ok(Self {
                file: File::from(fd),
            })
        }

        #[cfg(target_os = "linux")]
        pub fn open(interface_name: &str) -> io::Result<Self> {
            validate_interface_name(interface_name)?;

            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC)
                .open("/dev/net/tun")?;

            let mut request: libc::ifreq = unsafe { mem::zeroed() };
            let name = CString::new(interface_name).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
            })?;

            unsafe {
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    request.ifr_name.as_mut_ptr(),
                    name.as_bytes_with_nul().len(),
                );
                request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
                if libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut request) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            Ok(Self { file })
        }

        pub fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
            let fd = self.file.as_raw_fd();
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags < 0 {
                    return Err(io::Error::last_os_error());
                }
                let next_flags = if enabled {
                    flags | libc::O_NONBLOCK
                } else {
                    flags & !libc::O_NONBLOCK
                };
                if libc::fcntl(fd, libc::F_SETFL, next_flags) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        }

        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            unsafe {
                let result = libc::read(
                    self.file.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                );
                if result < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(result as usize)
            }
        }

        pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
            unsafe {
                let result = libc::write(
                    self.file.as_raw_fd(),
                    buf.as_ptr().cast::<libc::c_void>(),
                    buf.len(),
                );
                if result < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(result as usize)
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn validate_interface_name(interface_name: &str) -> io::Result<()> {
        if interface_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name must not be empty",
            ));
        }
        if interface_name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name exceeds IFNAMSIZ",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::SyncDevice;
        #[cfg(target_os = "linux")]
        use super::validate_interface_name;
        use std::io::{Read, Write};
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        // A connected stream socket pair stands in for the tun fd: `from_owned_fd`
        // must not care what kind of descriptor it adopts (the production caller
        // guarantees a TUN fd); only safe std APIs are used here so the vendored
        // unsafe census is unchanged.
        fn adopted_pair() -> (SyncDevice, UnixStream) {
            let (a, b) = UnixStream::pair().expect("socketpair");
            let device = SyncDevice::from_owned_fd(OwnedFd::from(a)).expect("adopt fd");
            (device, b)
        }

        #[test]
        fn adopted_fd_sends_and_receives_through_the_device() {
            let (device, mut peer) = adopted_pair();
            assert_eq!(device.send(&[0x45, 1, 2, 3]).expect("send"), 4);
            let mut got = [0u8; 8];
            let n = peer.read(&mut got).expect("peer read");
            assert_eq!(&got[..n], &[0x45, 1, 2, 3]);
            peer.write_all(&[0x60, 9]).expect("peer write");
            let mut buf = [0u8; 8];
            let n = device.recv(&mut buf).expect("recv");
            assert_eq!(&buf[..n], &[0x60, 9]);
        }

        #[test]
        fn adopted_fd_honours_nonblocking_mode() {
            let (device, _peer) = adopted_pair();
            device.set_nonblocking(true).expect("nonblocking on");
            let mut buf = [0u8; 8];
            let err = device
                .recv(&mut buf)
                .expect_err("empty queue must not block");
            assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        }

        #[test]
        fn dropping_the_device_closes_the_adopted_fd() {
            let (device, mut peer) = adopted_pair();
            peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("read timeout");
            drop(device);
            let mut buf = [0u8; 1];
            // The peer sees EOF only if the adopted fd was really closed.
            assert_eq!(peer.read(&mut buf).expect("eof read"), 0);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn rejects_empty_interface_name() {
            let err = validate_interface_name("").expect_err("empty name should fail");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn rejects_interface_names_that_exceed_ifnamsiz() {
            let oversized = "a".repeat(libc::IFNAMSIZ);
            let err = validate_interface_name(&oversized).expect_err("oversized name should fail");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::io;
    use std::mem::{self, size_of};
    use std::os::fd::RawFd;

    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
    const UTUN_HEADER_LEN: usize = 4;

    pub struct SyncDevice {
        fd: RawFd,
    }

    impl SyncDevice {
        /// Not supported on macOS: a utun descriptor needs the address-family
        /// framing handled by `from_raw_fd`/`open`, which is not the raw-IP contract
        /// of the Linux/Android constructor. Present for cross-platform callers.
        pub fn from_owned_fd(_fd: std::os::fd::OwnedFd) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "from_owned_fd is supported only on Linux and Android",
            ))
        }

        pub fn open(interface_name: &str) -> io::Result<Self> {
            let unit = parse_utun_unit(interface_name)?;
            let fd =
                unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let result = connect_utun_control(fd, unit);
            if let Err(err) = result {
                unsafe {
                    libc::close(fd);
                }
                return Err(err);
            }

            Ok(Self { fd })
        }

        pub fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
            let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            let next_flags = if enabled {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            };
            if unsafe { libc::fcntl(self.fd, libc::F_SETFL, next_flags) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut header = [0u8; UTUN_HEADER_LEN];
            let iov = [
                libc::iovec {
                    iov_base: header.as_mut_ptr().cast::<libc::c_void>(),
                    iov_len: header.len(),
                },
                libc::iovec {
                    iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
                    iov_len: buf.len(),
                },
            ];
            // SAFETY: `self.fd` is a valid open descriptor owned by `self`. Both
            // iovec entries point into live, exclusively borrowed buffers
            // (`header` and `buf`) with `iov_len` set to each buffer's exact
            // length, so the kernel scatter-read writes at most
            // `UTUN_HEADER_LEN + buf.len()` bytes and cannot write out of
            // bounds. Neither buffer is accessed through another reference
            // while the call runs, and the iovec array outlives the call.
            let result = unsafe { libc::readv(self.fd, iov.as_ptr(), iov.len() as libc::c_int) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            if result == 0 {
                // A live utun socket never yields a zero-length read: even a
                // header-only frame is 4 bytes. EOF means the control
                // socket's receive side was shut down (XNU does this to a
                // descriptor that is closed while still in flight over a
                // unix socket), after which the kernel can no longer hand
                // this interface any packet. Fail loudly instead of looking
                // like an idle tunnel.
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "utun control socket receive side is shut down (read returned EOF)",
                ));
            }
            let len = result as usize;
            if len <= UTUN_HEADER_LEN {
                return Ok(0);
            }
            let payload_len = len - UTUN_HEADER_LEN;
            if payload_len > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "utun payload exceeded caller buffer",
                ));
            }
            Ok(payload_len)
        }

        pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
            let family = packet_address_family(buf)?;
            let header = [0u8, 0, 0, family];
            let iov = [
                libc::iovec {
                    iov_base: header.as_ptr().cast_mut().cast::<libc::c_void>(),
                    iov_len: header.len(),
                },
                libc::iovec {
                    iov_base: buf.as_ptr().cast_mut().cast::<libc::c_void>(),
                    iov_len: buf.len(),
                },
            ];
            // SAFETY: `self.fd` is a valid open descriptor owned by `self`. Both
            // iovec entries point into live buffers (`header` and `buf`) with
            // `iov_len` set to each buffer's exact length. `writev` only reads
            // through `iov_base`, so casting away const is sound and neither
            // buffer is mutated. The iovec array outlives the call.
            let result = unsafe { libc::writev(self.fd, iov.as_ptr(), iov.len() as libc::c_int) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((result as usize).saturating_sub(UTUN_HEADER_LEN))
        }

        /// Reports whether the control socket can still receive packets from
        /// the kernel. A peek with `MSG_DONTWAIT` returns EAGAIN on a healthy
        /// idle socket and 0 (EOF) once its receive side has been shut down;
        /// in that state every packet the kernel routes to the interface fails
        /// with ENOBUFS (`utun_output - ctl_enqueuembuf failed: 55`).
        pub fn receive_side_open(&self) -> io::Result<bool> {
            let mut probe = [0u8; 1];
            // SAFETY: `self.fd` is a valid open descriptor owned by `self`;
            // `probe` is a live 1-byte buffer and the length passed matches
            // it. MSG_PEEK leaves any queued packet in place and
            // MSG_DONTWAIT guarantees the call cannot block.
            let result = unsafe {
                libc::recv(
                    self.fd,
                    probe.as_mut_ptr().cast::<libc::c_void>(),
                    probe.len(),
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            if result > 0 {
                return Ok(true);
            }
            if result == 0 {
                return Ok(false);
            }
            let err = io::Error::last_os_error();
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(true)
            } else {
                Err(err)
            }
        }

        pub fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
            if fd < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "utun fd must be non-negative",
                ));
            }
            Ok(Self { fd })
        }
    }

    impl Drop for SyncDevice {
        fn drop(&mut self) {
            if self.fd >= 0 {
                unsafe {
                    libc::close(self.fd);
                }
                self.fd = -1;
            }
        }
    }

    impl std::os::fd::IntoRawFd for SyncDevice {
        fn into_raw_fd(self) -> RawFd {
            let fd = self.fd;
            std::mem::forget(self);
            fd
        }
    }

    impl std::os::fd::AsRawFd for SyncDevice {
        fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }

    fn connect_utun_control(fd: RawFd, unit: u32) -> io::Result<()> {
        let mut info = libc::ctl_info {
            ctl_id: 0,
            ctl_name: [0; libc::MAX_KCTL_NAME],
        };
        for (dst, src) in info
            .ctl_name
            .iter_mut()
            .zip(UTUN_CONTROL_NAME.iter().copied())
        {
            *dst = src as libc::c_char;
        }

        if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let addr = libc::sockaddr_ctl {
            sc_len: size_of::<libc::sockaddr_ctl>() as libc::c_uchar,
            sc_family: libc::AF_SYSTEM as libc::c_uchar,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };

        if unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                mem::size_of_val(&addr) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn parse_utun_unit(interface_name: &str) -> io::Result<u32> {
        let suffix = interface_name.strip_prefix("utun").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name must start with utun",
            )
        })?;
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name must be utun followed by digits",
            ));
        }
        let index = suffix.parse::<u32>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "utun index is not numeric")
        })?;
        index.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "utun index exceeds u32 range")
        })
    }

    fn packet_address_family(buf: &[u8]) -> io::Result<u8> {
        let Some(first) = buf.first() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet must not be empty",
            ));
        };
        match first >> 4 {
            4 => Ok(libc::AF_INET as u8),
            6 => Ok(libc::AF_INET6 as u8),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet is not IPv4 or IPv6",
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{SyncDevice, UTUN_HEADER_LEN, packet_address_family, parse_utun_unit};
        use std::io;
        use std::os::fd::RawFd;

        /// Datagram socketpair standing in for the utun control socket: it
        /// preserves message boundaries the same way, so the readv/writev
        /// framing can be exercised end-to-end without a real utun device.
        fn datagram_socketpair() -> (SyncDevice, RawFd) {
            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: `fds` is a live 2-element array; socketpair writes
            // exactly two descriptors into it on success.
            let rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
            let device = SyncDevice::from_raw_fd(fds[0]).expect("wrap socketpair fd");
            (device, fds[1])
        }

        fn close_peer(fd: RawFd) {
            // SAFETY: `fd` is a live descriptor owned by the test.
            unsafe {
                libc::close(fd);
            }
        }

        fn set_peer_nonblocking(fd: RawFd) {
            // SAFETY: `fd` is a live descriptor owned by the test; fcntl with
            // F_GETFL/F_SETFL only manipulates its status flags.
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                assert!(flags >= 0, "F_GETFL failed: {}", io::Error::last_os_error());
                let rc = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                assert!(rc >= 0, "F_SETFL failed: {}", io::Error::last_os_error());
            }
        }

        fn read_peer_datagram(fd: RawFd, buf: &mut [u8]) -> isize {
            // SAFETY: `buf` is a live, exclusively borrowed buffer and the
            // read is bounded by its length.
            unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) }
        }

        fn write_peer_datagram(fd: RawFd, buf: &[u8]) {
            // SAFETY: `buf` is a live buffer and the write is bounded by its
            // length; `write` does not mutate it.
            let written =
                unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
            assert_eq!(written, buf.len() as isize, "peer datagram write failed");
        }

        #[test]
        fn send_prepends_utun_header_and_returns_payload_length() {
            let (device, peer) = datagram_socketpair();
            let payload = [0x45u8, 0xaa, 0xbb, 0xcc];
            let written = device.send(&payload).expect("send should succeed");
            assert_eq!(written, payload.len());

            let mut framed = [0u8; 64];
            let len = read_peer_datagram(peer, &mut framed);
            assert_eq!(len as usize, UTUN_HEADER_LEN + payload.len());
            assert_eq!(&framed[..UTUN_HEADER_LEN], &[0, 0, 0, libc::AF_INET as u8]);
            assert_eq!(&framed[UTUN_HEADER_LEN..len as usize], &payload);
            close_peer(peer);
        }

        #[test]
        fn send_marks_ipv6_packets_with_inet6_family() {
            let (device, peer) = datagram_socketpair();
            let payload = [0x60u8, 0, 0, 0];
            let written = device.send(&payload).expect("send should succeed");
            assert_eq!(written, payload.len());

            let mut framed = [0u8; 64];
            let len = read_peer_datagram(peer, &mut framed);
            assert_eq!(len as usize, UTUN_HEADER_LEN + payload.len());
            assert_eq!(&framed[..UTUN_HEADER_LEN], &[0, 0, 0, libc::AF_INET6 as u8]);
            close_peer(peer);
        }

        #[test]
        fn send_rejects_non_ip_frames_before_writing() {
            let (device, peer) = datagram_socketpair();
            let err = device
                .send(&[0x10, 1, 2])
                .expect_err("non-IP frame must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            let err = device.send(&[]).expect_err("empty frame must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

            // Nothing may have reached the wire: a nonblocking read on the
            // peer end must report an empty socket, not a stray datagram.
            set_peer_nonblocking(peer);
            let mut probe = [0u8; 8];
            let result = read_peer_datagram(peer, &mut probe);
            let read_err = io::Error::last_os_error();
            assert_eq!(result, -1, "rejected send must not emit a datagram");
            assert_eq!(read_err.kind(), io::ErrorKind::WouldBlock);
            close_peer(peer);
        }

        #[test]
        fn recv_strips_utun_header() {
            let (device, peer) = datagram_socketpair();
            let framed = [0u8, 0, 0, libc::AF_INET as u8, 0x45, 1, 2, 3];
            write_peer_datagram(peer, &framed);

            let mut buf = [0u8; 64];
            let len = device.recv(&mut buf).expect("recv should succeed");
            assert_eq!(&buf[..len], &[0x45, 1, 2, 3]);
            close_peer(peer);
        }

        #[test]
        fn recv_returns_zero_for_header_only_datagram() {
            let (device, peer) = datagram_socketpair();
            write_peer_datagram(peer, &[0u8, 0, 0, libc::AF_INET as u8]);

            let mut buf = [0u8; 64];
            let len = device
                .recv(&mut buf)
                .expect("header-only datagram should not error");
            assert_eq!(len, 0);
            close_peer(peer);
        }

        #[test]
        fn recv_reports_eof_when_receive_side_is_shut_down() {
            use std::os::fd::AsRawFd;
            let (device, peer) = datagram_socketpair();
            assert!(
                device.receive_side_open().expect("peek on a live socket"),
                "a fresh socket must report an open receive side"
            );
            // SAFETY: the device's descriptor is a live socket owned by the
            // test; shutdown only changes its state.
            let rc = unsafe { libc::shutdown(device.as_raw_fd(), libc::SHUT_RD) };
            assert_eq!(rc, 0, "shutdown failed: {}", io::Error::last_os_error());
            assert!(
                !device.receive_side_open().expect("peek after shutdown"),
                "a shut-down receive side must be detected"
            );
            let mut buf = [0u8; 64];
            let err = device
                .recv(&mut buf)
                .expect_err("EOF must surface as an error, not as an idle tunnel");
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            close_peer(peer);
        }

        #[test]
        fn receive_side_open_does_not_consume_queued_packets() {
            let (device, peer) = datagram_socketpair();
            write_peer_datagram(peer, &[0u8, 0, 0, libc::AF_INET as u8, 0x45, 9]);
            assert!(device.receive_side_open().expect("peek"));
            let mut buf = [0u8; 64];
            let len = device.recv(&mut buf).expect("packet must still be queued");
            assert_eq!(&buf[..len], &[0x45, 9]);
            close_peer(peer);
        }

        #[test]
        fn parses_named_utun_unit() {
            assert_eq!(parse_utun_unit("utun9").unwrap(), 10);
        }

        #[test]
        fn rejects_dynamic_or_non_utun_names() {
            assert!(parse_utun_unit("utun").is_err());
            assert!(parse_utun_unit("rustynet0").is_err());
            assert!(parse_utun_unit("utunx").is_err());
        }

        #[test]
        fn detects_packet_families() {
            assert_eq!(packet_address_family(&[0x45]).unwrap(), libc::AF_INET as u8);
            assert_eq!(
                packet_address_family(&[0x60]).unwrap(),
                libc::AF_INET6 as u8
            );
            assert!(packet_address_family(&[0x10]).is_err());
            assert!(packet_address_family(&[]).is_err());
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
mod imp {
    use std::io;

    pub struct SyncDevice;

    impl SyncDevice {
        pub fn from_owned_fd(_fd: std::os::fd::OwnedFd) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "from_owned_fd is supported only on Linux and Android",
            ))
        }

        pub fn open(_interface_name: &str) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rustynet-tun supports only Linux and macOS",
            ))
        }

        pub fn set_nonblocking(&self, _enabled: bool) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rustynet-tun supports only Linux and macOS",
            ))
        }

        pub fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rustynet-tun supports only Linux and macOS",
            ))
        }

        pub fn send(&self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rustynet-tun supports only Linux and macOS",
            ))
        }
    }
}

pub use imp::SyncDevice;

#[allow(dead_code)]
fn _io_marker(_: &io::Error) {}
