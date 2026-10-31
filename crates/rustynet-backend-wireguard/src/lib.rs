#![forbid(unsafe_code)]

#[cfg(any(test, feature = "test-harness"))]
pub mod bench_support;
mod in_memory;
mod linux_command;
mod macos_command;
mod udp_offload_probe;
mod userspace_shared;
#[cfg(not(target_os = "android"))]
mod userspace_shared_macos;
mod windows_command;

pub use in_memory::{
    RecordedAuthoritativeTransportOperation, RecordedAuthoritativeTransportOperationKind,
    WireguardBackend,
};
pub use linux_command::{
    LinuxCommandRunner, LinuxWireguardBackend, MIN_BRINGUP_TUNNEL_MTU, SAFE_BRINGUP_TUNNEL_MTU,
    TUNNEL_MTU_ENV, WireguardCommandOutput, WireguardCommandRunner, bringup_tunnel_mtu,
    resolve_bringup_tunnel_mtu,
};
pub use macos_command::{
    MacosWireguardBackend, WireguardGoProcessEntry, parse_wireguard_go_process_entries,
    validate_macos_wireguard_interface_name,
};
pub use udp_offload_probe::{
    OffloadSupport, UdpOffloadCapabilities, probe_udp_offload_capabilities,
};
pub use userspace_shared::LinuxUserspaceSharedBackend;
#[cfg(not(target_os = "android"))]
pub use userspace_shared_macos::MacosUserspaceSharedBackend;
/// Closure type for opening a macOS utun device via the privileged helper.
#[cfg(target_os = "macos")]
pub type MacosUtunOpenerFn =
    Box<dyn Fn(&str) -> Result<std::os::fd::OwnedFd, String> + Send + Sync>;
pub use windows_command::{
    DEFAULT_WINDOWS_NETSH_EXE_PATH, DEFAULT_WINDOWS_WG_EXE_PATH,
    DEFAULT_WINDOWS_WIREGUARD_EXE_PATH, WindowsWireguardBackend,
};

// AQ-213: per-crate compiled ground-truth gate for this crate's
// reviewed-redacting-impl registry entries; the source is shared with
// rustynetd via #[path] so every host crate runs the same gate.
#[cfg(test)]
#[path = "../../rustynetd/src/witness_listing.rs"]
mod witness_listing;
