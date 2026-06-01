use super::*;
use std::path::Path;
use std::time::Duration;

pub(super) mod windows;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BootstrapPhase {
    SyncSource,
    BuildRelease,
    SmokeServiceHost,
    InstallRelease,
    RestartRuntime,
    VerifyRuntime,
    /// Single-node WireGuard tunnel bring-up smoke (readiness plan N1). A
    /// standalone, manually-triggered phase — never part of `All` — because it
    /// performs a privileged live tunnel bring-up that requires an operator
    /// checkpoint. Windows-only; other platforms fail closed.
    TunnelSmoke,
    /// Single-node killswitch + fail-closed exercise (readiness plan N2). Like
    /// `TunnelSmoke` but additionally drives the killswitch through
    /// apply/assert/rollback on the live tunnel. Standalone, never part of `All`
    /// (privileged + checkpoint-gated, can momentarily affect egress). Windows-
    /// only; other platforms fail closed.
    KillswitchSmoke,
    /// Single-node DNS fail-closed exercise in protected mode (readiness plan
    /// N3). Runs the killswitch smoke with its DNS leg enabled: while the
    /// killswitch is active it applies/asserts/rolls back the netsh port-53
    /// LAN-block. Standalone, never part of `All`; Windows-only.
    DnsSmoke,
    All,
}

impl BootstrapPhase {
    pub(super) fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "sync-source" => Ok(Self::SyncSource),
            "build-release" => Ok(Self::BuildRelease),
            "smoke-service-host" => Ok(Self::SmokeServiceHost),
            "install-release" => Ok(Self::InstallRelease),
            "restart-runtime" => Ok(Self::RestartRuntime),
            "verify-runtime" => Ok(Self::VerifyRuntime),
            "tunnel-smoke" => Ok(Self::TunnelSmoke),
            "killswitch-smoke" => Ok(Self::KillswitchSmoke),
            "dns-smoke" => Ok(Self::DnsSmoke),
            "all" => Ok(Self::All),
            other => Err(format!(
                "unsupported vm-lab bootstrap phase: {other} (expected sync-source|build-release|smoke-service-host|install-release|restart-runtime|verify-runtime|tunnel-smoke|killswitch-smoke|dns-smoke|all)"
            )),
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::SyncSource => "sync-source",
            Self::BuildRelease => "build-release",
            Self::SmokeServiceHost => "smoke-service-host",
            Self::InstallRelease => "install-release",
            Self::RestartRuntime => "restart-runtime",
            Self::VerifyRuntime => "verify-runtime",
            Self::TunnelSmoke => "tunnel-smoke",
            Self::KillswitchSmoke => "killswitch-smoke",
            Self::DnsSmoke => "dns-smoke",
            Self::All => "all",
        }
    }
}

pub(super) struct BootstrapPhaseContext<'a> {
    pub(super) ssh_user: Option<&'a str>,
    pub(super) ssh_identity_file: Option<&'a Path>,
    pub(super) known_hosts_path: Option<&'a Path>,
    pub(super) workdir: &'a str,
    pub(super) repo_url: Option<&'a str>,
    pub(super) branch: &'a str,
    pub(super) remote: &'a str,
    pub(super) timeout: Duration,
}

pub(super) trait VmBootstrapProvider {
    fn platform(&self) -> VmGuestPlatform;
    fn execute_phase(
        &self,
        phase: BootstrapPhase,
        target: &RemoteTarget,
        context: &BootstrapPhaseContext<'_>,
    ) -> Result<(), String>;
}

pub(super) fn execute_bootstrap_phase_for_target(
    phase: &str,
    target: &RemoteTarget,
    context: &BootstrapPhaseContext<'_>,
) -> Result<(), String> {
    let phase = BootstrapPhase::parse(phase)?;
    match target.platform_profile.platform {
        VmGuestPlatform::Linux => {
            super::execute_legacy_posix_bootstrap_phase_for_target(phase, target, context)
        }
        VmGuestPlatform::Macos => Err(format!(
            "bootstrap phase {} is not yet implemented for macOS targets in the provider layer: {}",
            phase.as_str(),
            target.label
        )),
        VmGuestPlatform::Windows => {
            let provider: &dyn VmBootstrapProvider = &windows::WINDOWS_BOOTSTRAP_PROVIDER;
            if provider.platform() != target.platform_profile.platform {
                return Err(format!(
                    "bootstrap provider platform mismatch for {}: expected {}, got {}",
                    target.label,
                    target.platform_profile.platform.as_str(),
                    provider.platform().as_str()
                ));
            }
            provider.execute_phase(phase, target, context)
        }
        VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(format!(
            "bootstrap phase {} is intentionally scaffold-only for platform {}: {}",
            phase.as_str(),
            target.platform_profile.platform.as_str(),
            target.label
        )),
    }
}
