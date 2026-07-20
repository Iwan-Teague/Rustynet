//! FIS-0028 Phase 1: read-only detection of the host's UDP batching/offload
//! capability surface — `sendmmsg(2)`/`recvmmsg(2)` syscall batching and the
//! Linux `UDP_SEGMENT` (UDP GSO) / `UDP_GRO` socket options that later phases
//! of the proposal would use to amortize the one-syscall-per-frame cost on the
//! authoritative dataplane socket.
//!
//! Phase 1 scope, deliberately inert:
//! - Nothing on any packet send or receive path calls this module. The
//!   authoritative pump (`userspace_shared`/`userspace_shared_macos`) is
//!   unchanged and still performs one `send_to`/`recv_from` per datagram.
//! - The probe never binds to a caller-visible port, never connects, and never
//!   sends or receives a datagram. The only socket it creates is an unbound
//!   throwaway used to prove `socket2` can construct and configure a UDP
//!   socket on this host; it is dropped (closed) before the probe returns.
//! - The probe is infallible by design: every failure mode (missing procfs
//!   entry, unparseable kernel release, socket creation denied) folds into an
//!   `Unsupported { reason }` verdict instead of an error or a panic, so a
//!   platform without the syscalls degrades gracefully to "keep the proven
//!   per-frame path".
//!
//! Detection method and its honest limits: `socket2` 0.6 exposes no typed
//! helpers for `UDP_SEGMENT`/`UDP_GRO`, and its arbitrary
//! `setsockopt`/`getsockopt` entry points are crate-private `unsafe` — while
//! this workspace forbids `unsafe` in first-party crates — so a live
//! set-the-option probe is not expressible here today. Phase 1 therefore
//! gates each capability on the running kernel release
//! (`/proc/sys/kernel/osrelease`), using the kernel versions where each
//! feature landed upstream. These verdicts are advisory capability hints:
//! a later batched path must still treat any runtime syscall failure
//! (seccomp denial, container filtering) as "fall back to the per-frame
//! path", exactly as the proposal's fail-closed design already requires.
//! Non-Linux hosts report every batching capability as unsupported.

use std::fmt;

// The kernel-release gates and their parser are exercised by the Linux
// production path and by the host-independent unit tests; non-Linux
// production builds have no caller (their probe short-circuits to
// "Linux-specific"), so the items are compiled out there to keep the
// build warning-free under `-D warnings`.
/// Kernel release where `sendmmsg(2)` landed upstream (Linux 3.0, 2011).
#[cfg(any(target_os = "linux", test))]
const SENDMMSG_MIN_KERNEL: (u32, u32, u32) = (3, 0, 0);
/// Kernel release where `recvmmsg(2)` landed upstream (Linux 2.6.33, 2010).
#[cfg(any(target_os = "linux", test))]
const RECVMMSG_MIN_KERNEL: (u32, u32, u32) = (2, 6, 33);
/// Kernel release where the `UDP_SEGMENT` (UDP GSO) socket option landed
/// upstream (Linux 4.18, 2018).
#[cfg(any(target_os = "linux", test))]
const UDP_SEGMENT_MIN_KERNEL: (u32, u32, u32) = (4, 18, 0);
/// Kernel release where the `UDP_GRO` socket option landed upstream
/// (Linux 5.0, 2019).
#[cfg(any(target_os = "linux", test))]
const UDP_GRO_MIN_KERNEL: (u32, u32, u32) = (5, 0, 0);

const SENDMMSG_SYMBOL: &str = "sendmmsg(2)";
const RECVMMSG_SYMBOL: &str = "recvmmsg(2)";
const UDP_SEGMENT_SYMBOL: &str = "UDP_SEGMENT (UDP GSO)";
const UDP_GRO_SYMBOL: &str = "UDP_GRO";

/// Support verdict for one UDP batching/offload capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OffloadSupport {
    /// The capability is expected to work on this OS/kernel.
    Supported,
    /// The capability is not available here; `reason` records why (wrong OS,
    /// kernel predates the feature, probe machinery failed).
    Unsupported {
        /// Human-readable explanation of why the capability is unavailable.
        reason: String,
    },
}

impl OffloadSupport {
    /// True when the capability is expected to work on this host.
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported)
    }

    /// The unsupported reason, when there is one.
    pub fn unsupported_reason(&self) -> Option<&str> {
        match self {
            Self::Supported => None,
            Self::Unsupported { reason } => Some(reason.as_str()),
        }
    }
}

/// Snapshot of the host's UDP batching/offload capability surface, as
/// detected by [`probe_udp_offload_capabilities`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpOffloadCapabilities {
    /// `sendmmsg(2)` — batched egress syscall (Linux >= 3.0).
    pub sendmmsg: OffloadSupport,
    /// `recvmmsg(2)` — batched ingress syscall (Linux >= 2.6.33).
    pub recvmmsg: OffloadSupport,
    /// `UDP_SEGMENT` socket option — UDP generic segmentation offload on
    /// egress (Linux >= 4.18).
    pub udp_segment: OffloadSupport,
    /// `UDP_GRO` socket option — UDP generic receive offload on ingress
    /// (Linux >= 5.0).
    pub udp_gro: OffloadSupport,
    /// Whether `socket2` can construct and configure (non-blocking) a UDP
    /// socket on this host — the plumbing a later phase would use to wrap the
    /// authoritative socket's file descriptor.
    pub socket2_udp_plumbing: OffloadSupport,
    /// The raw kernel release string the verdicts were derived from
    /// (`/proc/sys/kernel/osrelease`; Linux only, `None` elsewhere or when
    /// unreadable).
    pub kernel_release: Option<String>,
}

impl fmt::Display for UdpOffloadCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn yes_no(support: &OffloadSupport) -> &'static str {
            if support.is_supported() { "yes" } else { "no" }
        }
        write!(
            f,
            "sendmmsg={} recvmmsg={} udp_segment={} udp_gro={} socket2_udp_plumbing={} kernel_release={}",
            yes_no(&self.sendmmsg),
            yes_no(&self.recvmmsg),
            yes_no(&self.udp_segment),
            yes_no(&self.udp_gro),
            yes_no(&self.socket2_udp_plumbing),
            self.kernel_release.as_deref().unwrap_or("n/a"),
        )
    }
}

/// Detect the host's UDP batching/offload capability surface.
///
/// Read-only and side-effect free with respect to the dataplane: no existing
/// socket is touched, no port is bound, and no datagram is sent or received.
/// Infallible: failures degrade to `Unsupported { reason }`, never an error
/// or a panic. Not called from any packet-forwarding path in Phase 1.
pub fn probe_udp_offload_capabilities() -> UdpOffloadCapabilities {
    let socket2_udp_plumbing = probe_socket2_udp_plumbing();

    #[cfg(target_os = "linux")]
    {
        match read_kernel_release() {
            Ok(release) => UdpOffloadCapabilities {
                sendmmsg: kernel_gate(&release, SENDMMSG_MIN_KERNEL, SENDMMSG_SYMBOL),
                recvmmsg: kernel_gate(&release, RECVMMSG_MIN_KERNEL, RECVMMSG_SYMBOL),
                udp_segment: kernel_gate(&release, UDP_SEGMENT_MIN_KERNEL, UDP_SEGMENT_SYMBOL),
                udp_gro: kernel_gate(&release, UDP_GRO_MIN_KERNEL, UDP_GRO_SYMBOL),
                socket2_udp_plumbing,
                kernel_release: Some(release),
            },
            Err(read_error) => {
                let unavailable = |symbol: &str| OffloadSupport::Unsupported {
                    reason: format!(
                        "kernel release unavailable ({read_error}); treating {symbol} as unsupported"
                    ),
                };
                UdpOffloadCapabilities {
                    sendmmsg: unavailable(SENDMMSG_SYMBOL),
                    recvmmsg: unavailable(RECVMMSG_SYMBOL),
                    udp_segment: unavailable(UDP_SEGMENT_SYMBOL),
                    udp_gro: unavailable(UDP_GRO_SYMBOL),
                    socket2_udp_plumbing,
                    kernel_release: None,
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let host_os = std::env::consts::OS;
        let linux_only = |symbol: &str| OffloadSupport::Unsupported {
            reason: format!(
                "{symbol} batching is Linux-specific; host OS '{host_os}' keeps the per-frame path"
            ),
        };
        UdpOffloadCapabilities {
            sendmmsg: linux_only(SENDMMSG_SYMBOL),
            recvmmsg: linux_only(RECVMMSG_SYMBOL),
            udp_segment: linux_only(UDP_SEGMENT_SYMBOL),
            udp_gro: linux_only(UDP_GRO_SYMBOL),
            socket2_udp_plumbing,
            kernel_release: None,
        }
    }
}

/// Prove `socket2` can construct and configure a UDP socket on this host.
///
/// The probe socket is never bound, never connected, and never carries a
/// datagram; it exists only to exercise the safe wrapper a later phase would
/// use around the authoritative socket's file descriptor, and it is closed
/// (dropped) before this function returns.
fn probe_socket2_udp_plumbing() -> OffloadSupport {
    let socket = match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(socket) => socket,
        Err(err) => {
            return OffloadSupport::Unsupported {
                reason: format!("socket2 UDP probe socket creation failed: {err}"),
            };
        }
    };
    if let Err(err) = socket.set_nonblocking(true) {
        return OffloadSupport::Unsupported {
            reason: format!("socket2 set_nonblocking failed on the UDP probe socket: {err}"),
        };
    }
    OffloadSupport::Supported
}

/// Read the running kernel release from procfs.
#[cfg(target_os = "linux")]
fn read_kernel_release() -> Result<String, String> {
    match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Err("/proc/sys/kernel/osrelease is empty".to_owned())
            } else {
                Ok(trimmed.to_owned())
            }
        }
        Err(err) => Err(format!("failed to read /proc/sys/kernel/osrelease: {err}")),
    }
}

/// Gate one capability on the parsed kernel release meeting a minimum
/// version. Unparseable input degrades to `Unsupported`, never a panic.
#[cfg(any(target_os = "linux", test))]
fn kernel_gate(release: &str, min: (u32, u32, u32), symbol: &str) -> OffloadSupport {
    match parse_kernel_release(release) {
        Some(version) if version >= min => OffloadSupport::Supported,
        Some((major, minor, patch)) => OffloadSupport::Unsupported {
            reason: format!(
                "kernel release '{release}' (parsed {major}.{minor}.{patch}) predates Linux {}.{}.{} where {symbol} landed",
                min.0, min.1, min.2
            ),
        },
        None => OffloadSupport::Unsupported {
            reason: format!("could not parse kernel release '{release}' for {symbol} detection"),
        },
    }
}

/// Parse the leading `major.minor[.patch]` triple out of a kernel release
/// string such as `6.8.0-134-generic`. Returns `None` when fewer than two
/// numeric components are present or a component overflows `u32` — callers
/// treat `None` as "cannot judge, report unsupported".
#[cfg(any(target_os = "linux", test))]
fn parse_kernel_release(release: &str) -> Option<(u32, u32, u32)> {
    let mut components: Vec<u32> = Vec::with_capacity(3);
    let mut current: Option<u32> = None;
    for ch in release.chars() {
        match ch.to_digit(10) {
            Some(digit) => {
                let extended = current
                    .unwrap_or(0)
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(digit))?;
                current = Some(extended);
            }
            None => {
                if let Some(value) = current.take() {
                    components.push(value);
                    if components.len() == 3 {
                        break;
                    }
                }
            }
        }
    }
    if let Some(value) = current
        && components.len() < 3
    {
        components.push(value);
    }
    match components.as_slice() {
        [major, minor, patch, ..] => Some((*major, *minor, *patch)),
        [major, minor] => Some((*major, *minor, 0)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kernel_release_handles_common_forms() {
        assert_eq!(parse_kernel_release("6.8.0-134-generic"), Some((6, 8, 0)));
        assert_eq!(parse_kernel_release("5.15.0"), Some((5, 15, 0)));
        assert_eq!(parse_kernel_release("4.18"), Some((4, 18, 0)));
        assert_eq!(parse_kernel_release("2.6.33"), Some((2, 6, 33)));
        assert_eq!(parse_kernel_release("5.10.0-rc2"), Some((5, 10, 0)));
    }

    #[test]
    fn parse_kernel_release_rejects_unusable_input() {
        assert_eq!(parse_kernel_release(""), None);
        assert_eq!(parse_kernel_release("generic"), None);
        assert_eq!(parse_kernel_release("6"), None);
        // A component overflowing u32 aborts the parse conservatively.
        assert_eq!(parse_kernel_release("99999999999.0.0"), None);
    }

    #[test]
    fn kernel_gate_thresholds_are_inclusive_at_the_landing_release() {
        // recvmmsg: Linux 2.6.33.
        assert!(!kernel_gate("2.6.32", RECVMMSG_MIN_KERNEL, RECVMMSG_SYMBOL).is_supported());
        assert!(kernel_gate("2.6.33", RECVMMSG_MIN_KERNEL, RECVMMSG_SYMBOL).is_supported());
        // sendmmsg: Linux 3.0.
        assert!(!kernel_gate("2.6.39", SENDMMSG_MIN_KERNEL, SENDMMSG_SYMBOL).is_supported());
        assert!(kernel_gate("3.0.0", SENDMMSG_MIN_KERNEL, SENDMMSG_SYMBOL).is_supported());
        // UDP_SEGMENT: Linux 4.18.
        assert!(!kernel_gate("4.17.19", UDP_SEGMENT_MIN_KERNEL, UDP_SEGMENT_SYMBOL).is_supported());
        assert!(kernel_gate("4.18", UDP_SEGMENT_MIN_KERNEL, UDP_SEGMENT_SYMBOL).is_supported());
        // UDP_GRO: Linux 5.0.
        assert!(!kernel_gate("4.20.17", UDP_GRO_MIN_KERNEL, UDP_GRO_SYMBOL).is_supported());
        assert!(kernel_gate("5.0.0", UDP_GRO_MIN_KERNEL, UDP_GRO_SYMBOL).is_supported());
        // A modern kernel clears every gate.
        for (min, symbol) in [
            (SENDMMSG_MIN_KERNEL, SENDMMSG_SYMBOL),
            (RECVMMSG_MIN_KERNEL, RECVMMSG_SYMBOL),
            (UDP_SEGMENT_MIN_KERNEL, UDP_SEGMENT_SYMBOL),
            (UDP_GRO_MIN_KERNEL, UDP_GRO_SYMBOL),
        ] {
            assert!(kernel_gate("6.8.0-134-generic", min, symbol).is_supported());
        }
    }

    #[test]
    fn kernel_gate_degrades_to_unsupported_on_unparseable_release() {
        let verdict = kernel_gate("not-a-kernel", UDP_GRO_MIN_KERNEL, UDP_GRO_SYMBOL);
        assert!(!verdict.is_supported());
        let reason = verdict
            .unsupported_reason()
            .expect("unsupported verdict carries a reason");
        assert!(reason.contains("could not parse"), "reason was: {reason}");
    }

    #[test]
    fn probe_on_this_host_returns_without_panic_and_is_consistent() {
        let first = probe_udp_offload_capabilities();
        let second = probe_udp_offload_capabilities();
        assert_eq!(
            first, second,
            "back-to-back probes on an unchanged host must agree"
        );
        assert!(
            first.socket2_udp_plumbing.is_supported(),
            "socket2 UDP plumbing probe failed on a host that runs this test suite: {:?}",
            first.socket2_udp_plumbing.unsupported_reason()
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn probe_reports_unsupported_rather_than_panicking_off_linux() {
        let capabilities = probe_udp_offload_capabilities();
        for (name, verdict) in [
            ("sendmmsg", &capabilities.sendmmsg),
            ("recvmmsg", &capabilities.recvmmsg),
            ("udp_segment", &capabilities.udp_segment),
            ("udp_gro", &capabilities.udp_gro),
        ] {
            assert!(
                !verdict.is_supported(),
                "{name} must be unsupported off Linux"
            );
            let reason = verdict
                .unsupported_reason()
                .expect("unsupported verdict carries a reason");
            assert!(
                reason.contains("Linux-specific"),
                "{name} reason should name the platform gap, was: {reason}"
            );
        }
        assert!(capabilities.kernel_release.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_derives_verdicts_from_the_host_kernel_release() {
        let capabilities = probe_udp_offload_capabilities();
        let release = capabilities
            .kernel_release
            .as_deref()
            .expect("a linux host exposes /proc/sys/kernel/osrelease");
        assert!(!release.is_empty());
        assert_eq!(
            capabilities.sendmmsg,
            kernel_gate(release, SENDMMSG_MIN_KERNEL, SENDMMSG_SYMBOL)
        );
        assert_eq!(
            capabilities.recvmmsg,
            kernel_gate(release, RECVMMSG_MIN_KERNEL, RECVMMSG_SYMBOL)
        );
        assert_eq!(
            capabilities.udp_segment,
            kernel_gate(release, UDP_SEGMENT_MIN_KERNEL, UDP_SEGMENT_SYMBOL)
        );
        assert_eq!(
            capabilities.udp_gro,
            kernel_gate(release, UDP_GRO_MIN_KERNEL, UDP_GRO_SYMBOL)
        );
        // Any kernel a maintained CI/lab host runs (>= 5.0) clears all four
        // gates; only assert when the parse says the host is that modern so
        // the test stays honest on ancient kernels.
        if let Some(version) = parse_kernel_release(release)
            && version >= UDP_GRO_MIN_KERNEL
        {
            assert!(capabilities.sendmmsg.is_supported());
            assert!(capabilities.recvmmsg.is_supported());
            assert!(capabilities.udp_segment.is_supported());
            assert!(capabilities.udp_gro.is_supported());
        }
    }

    #[test]
    fn display_is_a_compact_single_line() {
        let rendered = probe_udp_offload_capabilities().to_string();
        assert!(!rendered.contains('\n'));
        for token in [
            "sendmmsg=",
            "recvmmsg=",
            "udp_segment=",
            "udp_gro=",
            "socket2_udp_plumbing=",
            "kernel_release=",
        ] {
            assert!(rendered.contains(token), "missing '{token}' in: {rendered}");
        }
    }
}
