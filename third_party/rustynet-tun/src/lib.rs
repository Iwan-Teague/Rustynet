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

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;

    pub struct SyncDevice;

    impl SyncDevice {
        pub fn open(_interface_name: &str) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rustynet-tun supports only Linux",
            ))
        }

        pub fn set_nonblocking(&self, _enabled: bool) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rustynet-tun supports only Linux",
            ))
        }

        pub fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rustynet-tun supports only Linux",
            ))
        }

        pub fn send(&self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rustynet-tun supports only Linux",
            ))
        }
    }
}

pub use imp::SyncDevice;

#[allow(dead_code)]
fn _io_marker(_: &io::Error) {}
