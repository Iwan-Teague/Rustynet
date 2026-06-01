//! Single-node WireGuard-NT tunnel bring-up smoke (readiness plan N1).
//!
//! Proves the Windows data-plane end to end without a mesh: generate an
//! ephemeral keypair, bring up a self-only `rustynet0` tunnel via
//! `WindowsWireguardBackend` (DPAPI-sealed config + `wireguard.exe
//! /installtunnelservice` + `netsh` address), confirm the adapter is present
//! (`GetAdaptersAddresses`) and `wg show` works, then tear it down. No peers
//! and no killswitch — this exercises interface bring-up only. The killswitch
//! / protected-mode exercise is readiness-plan step N2.

use serde::Serialize;

/// Tunnel-smoke inputs. Defaults bring up a self-only `rustynet0` on a
/// CGNAT-range address with no peers and no killswitch.
#[derive(Debug, Clone)]
pub struct WindowsTunnelSmokeOptions {
    pub tunnel_name: String,
    pub address: String,
    pub mesh_cidr: String,
    pub listen_port: u16,
    /// Leave the tunnel up after the smoke instead of tearing it down (for
    /// manual inspection on the guest).
    pub keep: bool,
}

impl Default for WindowsTunnelSmokeOptions {
    fn default() -> Self {
        Self {
            tunnel_name: "rustynet0".to_owned(),
            address: "100.64.0.1/32".to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            listen_port: 51820,
            keep: false,
        }
    }
}

/// Fixed-shape smoke result the orchestrator can parse.
#[derive(Debug, Clone, Serialize)]
pub struct WindowsTunnelSmokeReport {
    pub tunnel_name: String,
    pub address: String,
    pub started: bool,
    pub interface_present: bool,
    pub wg_show_ok: bool,
    pub kept_up: bool,
    pub torn_down: bool,
    pub overall_ok: bool,
}

impl WindowsTunnelSmokeReport {
    /// Pure verdict so the pass/fail logic is unit-testable off-Windows: a
    /// smoke passes when the tunnel started, the adapter is present, `wg show`
    /// works, and it was cleanly torn down — unless `--keep` deliberately left
    /// it up.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn evaluate(
        options: &WindowsTunnelSmokeOptions,
        started: bool,
        interface_present: bool,
        wg_show_ok: bool,
        torn_down: bool,
    ) -> Self {
        let teardown_ok = options.keep || torn_down;
        Self {
            tunnel_name: options.tunnel_name.clone(),
            address: options.address.clone(),
            started,
            interface_present,
            wg_show_ok,
            kept_up: options.keep,
            torn_down,
            overall_ok: started && interface_present && wg_show_ok && teardown_ok,
        }
    }
}

/// Bring up a single self-only tunnel, verify it, and tear it down.
///
/// Returns `Err` if the tunnel cannot be brought up or (without `--keep`)
/// cannot be torn down — a tunnel left up is a leak, so that surfaces as a
/// hard failure. On success the `overall_ok` field of the report reflects
/// whether the adapter and `wg show` checks also passed.
#[cfg(windows)]
pub fn run_windows_tunnel_smoke(
    options: &WindowsTunnelSmokeOptions,
) -> Result<WindowsTunnelSmokeReport, String> {
    use rustynet_backend_api::{NodeId, RuntimeContext, TunnelBackend};
    use rustynet_backend_wireguard::{
        DEFAULT_WINDOWS_NETSH_EXE_PATH, DEFAULT_WINDOWS_WG_EXE_PATH,
        DEFAULT_WINDOWS_WIREGUARD_EXE_PATH, WindowsWireguardBackend,
    };

    // Ephemeral keypair -> plaintext-base64 key file (0600) in a temp dir. The
    // backend reads this once at config-render time and seals the rendered
    // config with DPAPI, so the plaintext key is removed immediately after the
    // tunnel comes up to keep its on-disk lifetime minimal.
    let (private_key, _public_key) = crate::key_material::generate_wireguard_keypair()?;
    let key_dir = std::env::temp_dir().join("rustynet-tunnel-smoke");
    std::fs::create_dir_all(key_dir.as_path())
        .map_err(|err| format!("create smoke key dir failed ({}): {err}", key_dir.display()))?;
    let key_path = key_dir.join(format!("{}.key", options.tunnel_name));
    crate::key_material::write_runtime_private_key(key_path.as_path(), &private_key)?;

    let config_path = crate::windows_paths::default_windows_tunnel_service_config_path(
        options.tunnel_name.as_str(),
    );
    let mut backend = WindowsWireguardBackend::new(
        crate::daemon::WindowsHostWireguardRunner,
        options.tunnel_name.clone(),
        config_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
        DEFAULT_WINDOWS_WIREGUARD_EXE_PATH,
        DEFAULT_WINDOWS_WG_EXE_PATH,
        DEFAULT_WINDOWS_NETSH_EXE_PATH,
        options.listen_port,
    )
    .map_err(|err| format!("construct windows wireguard backend failed: {err}"))?;

    let context = RuntimeContext {
        local_node: NodeId::new("windows-tunnel-smoke")
            .map_err(|err| format!("build smoke node id failed: {err}"))?,
        interface_name: options.tunnel_name.clone(),
        mesh_cidr: options.mesh_cidr.clone(),
        local_cidr: options.address.clone(),
    };

    let start_result = backend.start(context);
    // The plaintext key is no longer needed once the (now DPAPI-sealed) config
    // has been rendered, whether or not start succeeded.
    let _ = crate::key_material::remove_file_if_present(key_path.as_path());
    start_result.map_err(|err| format!("tunnel bring-up failed: {err}"))?;

    let interface_present = windows_adapter_present(options.tunnel_name.as_str());
    let wg_show_ok = backend.stats().is_ok();

    let torn_down = if options.keep {
        false
    } else {
        backend
            .shutdown()
            .map_err(|err| format!("tunnel teardown failed (tunnel left up): {err}"))?;
        true
    };

    Ok(WindowsTunnelSmokeReport::evaluate(
        options,
        true,
        interface_present,
        wg_show_ok,
        torn_down,
    ))
}

/// True if an adapter with the tunnel's friendly/adapter name is enumerated by
/// the OS, confirming the wintun adapter actually materialised.
#[cfg(windows)]
fn windows_adapter_present(tunnel_name: &str) -> bool {
    match rustynet_windows_native::get_adapters_addresses() {
        Ok(adapters) => adapters.iter().any(|adapter| {
            adapter.friendly_name.eq_ignore_ascii_case(tunnel_name)
                || adapter.adapter_name.eq_ignore_ascii_case(tunnel_name)
        }),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_passes_when_up_verified_and_torn_down() {
        let report = WindowsTunnelSmokeReport::evaluate(
            &WindowsTunnelSmokeOptions::default(),
            true,
            true,
            true,
            true,
        );
        assert!(report.overall_ok);
        assert!(!report.kept_up);
        assert!(report.torn_down);
    }

    #[test]
    fn evaluate_keep_does_not_require_teardown() {
        let options = WindowsTunnelSmokeOptions {
            keep: true,
            ..Default::default()
        };
        let report = WindowsTunnelSmokeReport::evaluate(&options, true, true, true, false);
        assert!(
            report.overall_ok,
            "an intentionally kept-up tunnel still passes without teardown"
        );
        assert!(report.kept_up);
        assert!(!report.torn_down);
    }

    #[test]
    fn evaluate_fails_when_adapter_missing() {
        let report = WindowsTunnelSmokeReport::evaluate(
            &WindowsTunnelSmokeOptions::default(),
            true,
            false,
            true,
            true,
        );
        assert!(!report.overall_ok);
    }

    #[test]
    fn evaluate_fails_on_leak_without_keep() {
        // Tunnel came up but was not torn down and --keep was not set: a leak,
        // which must fail.
        let report = WindowsTunnelSmokeReport::evaluate(
            &WindowsTunnelSmokeOptions::default(),
            true,
            true,
            true,
            false,
        );
        assert!(!report.overall_ok);
    }
}
