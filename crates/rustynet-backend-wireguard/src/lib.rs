#![forbid(unsafe_code)]

mod in_memory;
mod linux_command;
mod macos_command;
mod userspace_shared;

pub use in_memory::{
    RecordedAuthoritativeTransportOperation, RecordedAuthoritativeTransportOperationKind,
    WireguardBackend,
};
pub use linux_command::{
    LinuxCommandRunner, LinuxWireguardBackend, WireguardCommandOutput, WireguardCommandRunner,
};
pub use macos_command::MacosWireguardBackend;
pub use userspace_shared::LinuxUserspaceSharedBackend;
