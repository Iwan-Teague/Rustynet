use std::io;

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::mem;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    const TUNSETIFF: libc::c_ulong = 0x400454ca;

    pub struct SyncDevice {
        file: File,
    }

    impl SyncDevice {
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
        use super::validate_interface_name;

        #[test]
        fn rejects_empty_interface_name() {
            let err = validate_interface_name("").expect_err("empty name should fail");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }

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
            let mut framed = vec![0u8; buf.len().saturating_add(UTUN_HEADER_LEN)];
            let result = unsafe {
                libc::read(
                    self.fd,
                    framed.as_mut_ptr().cast::<libc::c_void>(),
                    framed.len(),
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
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
            buf[..payload_len]
                .copy_from_slice(&framed[UTUN_HEADER_LEN..UTUN_HEADER_LEN + payload_len]);
            Ok(payload_len)
        }

        pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
            let family = packet_address_family(buf)?;
            let mut framed = Vec::with_capacity(UTUN_HEADER_LEN + buf.len());
            framed.extend_from_slice(&[0, 0, 0, family]);
            framed.extend_from_slice(buf);
            let result = unsafe {
                libc::write(
                    self.fd,
                    framed.as_ptr().cast::<libc::c_void>(),
                    framed.len(),
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((result as usize).saturating_sub(UTUN_HEADER_LEN))
        }
    }

    impl Drop for SyncDevice {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
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
        use super::{packet_address_family, parse_utun_unit};

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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::io;

    pub struct SyncDevice;

    impl SyncDevice {
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
