#![forbid(unsafe_code)]

mod in_memory;
mod linux_command;
mod macos_command;
mod userspace_shared;
mod windows_command;

pub use in_memory::{
    RecordedAuthoritativeTransportOperation, RecordedAuthoritativeTransportOperationKind,
    WireguardBackend,
};
pub use linux_command::{
    LinuxCommandRunner, LinuxWireguardBackend, WireguardCommandOutput, WireguardCommandRunner,
};
pub use macos_command::MacosWireguardBackend;
pub use userspace_shared::LinuxUserspaceSharedBackend;
pub use windows_command::{
    DEFAULT_WINDOWS_NETSH_EXE_PATH, DEFAULT_WINDOWS_WG_EXE_PATH,
    DEFAULT_WINDOWS_WIREGUARD_EXE_PATH, WindowsWireguardBackend,
};
