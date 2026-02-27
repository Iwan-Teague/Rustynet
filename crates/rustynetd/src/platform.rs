#![forbid(unsafe_code)]

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPlatform {
    Linux,
    MacOs,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformIntegrationStatus {
    pub platform: ClientPlatform,
    pub route_hook_ready: bool,
    pub dns_hook_ready: bool,
    pub firewall_hook_ready: bool,
    pub leak_matrix_passed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformParityError {
    MissingRouteHook,
    MissingDnsHook,
    MissingFirewallHook,
    LeakMatrixFailed,
}

impl fmt::Display for PlatformParityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformParityError::MissingRouteHook => f.write_str("missing route hook"),
            PlatformParityError::MissingDnsHook => f.write_str("missing dns hook"),
            PlatformParityError::MissingFirewallHook => f.write_str("missing firewall hook"),
            PlatformParityError::LeakMatrixFailed => f.write_str("leak matrix did not pass"),
        }
    }
}

impl std::error::Error for PlatformParityError {}

pub fn validate_platform_parity(
    status: PlatformIntegrationStatus,
) -> Result<(), PlatformParityError> {
    if !status.route_hook_ready {
        return Err(PlatformParityError::MissingRouteHook);
    }
    if !status.dns_hook_ready {
        return Err(PlatformParityError::MissingDnsHook);
    }
    if !status.firewall_hook_ready {
        return Err(PlatformParityError::MissingFirewallHook);
    }
    if !status.leak_matrix_passed {
        return Err(PlatformParityError::LeakMatrixFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ClientPlatform, PlatformIntegrationStatus, PlatformParityError, validate_platform_parity,
    };

    #[test]
    fn macos_and_windows_parity_checks_pass_when_hooks_are_ready() {
        for platform in [ClientPlatform::MacOs, ClientPlatform::Windows] {
            let status = PlatformIntegrationStatus {
                platform,
                route_hook_ready: true,
                dns_hook_ready: true,
                firewall_hook_ready: true,
                leak_matrix_passed: true,
            };
            assert!(validate_platform_parity(status).is_ok());
        }
    }

    #[test]
    fn parity_check_fails_when_leak_matrix_is_not_green() {
        let status = PlatformIntegrationStatus {
            platform: ClientPlatform::Windows,
            route_hook_ready: true,
            dns_hook_ready: true,
            firewall_hook_ready: true,
            leak_matrix_passed: false,
        };
        assert_eq!(
            validate_platform_parity(status).err(),
            Some(PlatformParityError::LeakMatrixFailed)
        );
    }
}
