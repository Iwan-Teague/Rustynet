#![forbid(unsafe_code)]

#[cfg(any(test, feature = "test-harness"))]
pub mod bench_support;
mod in_memory;
mod linux_command;
mod macos_command;
mod udp_offload_probe;
mod userspace_shared;
mod userspace_shared_macos;
mod windows_command;

pub use in_memory::{
    RecordedAuthoritativeTransportOperation, RecordedAuthoritativeTransportOperationKind,
    WireguardBackend,
};
pub use linux_command::{
    LinuxCommandRunner, LinuxWireguardBackend, WireguardCommandOutput, WireguardCommandRunner,
};
pub use macos_command::MacosWireguardBackend;
pub use udp_offload_probe::{
    OffloadSupport, UdpOffloadCapabilities, probe_udp_offload_capabilities,
};
pub use userspace_shared::LinuxUserspaceSharedBackend;
pub use userspace_shared_macos::MacosUserspaceSharedBackend;
/// Closure type for opening a macOS utun device via the privileged helper.
#[cfg(target_os = "macos")]
pub type MacosUtunOpenerFn =
    Box<dyn Fn(&str) -> Result<std::os::fd::OwnedFd, String> + Send + Sync>;
pub use windows_command::{
    DEFAULT_WINDOWS_NETSH_EXE_PATH, DEFAULT_WINDOWS_WG_EXE_PATH,
    DEFAULT_WINDOWS_WIREGUARD_EXE_PATH, WindowsWireguardBackend,
};
