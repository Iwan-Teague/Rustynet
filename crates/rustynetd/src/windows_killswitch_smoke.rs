//! Single-node killswitch + fail-closed exercise (readiness plan N2).
//!
//! Builds on the N1 tunnel-smoke: bring up a self-only `rustynet0` tunnel, then
//! drive the real Windows killswitch `System` (`WindowsCommandSystem`) through
//! apply -> assert-active -> rollback -> assert-inactive, proving the netsh
//! default-block-outbound policy + the native WFP tunnel-permit (E2) actually
//! apply and roll back live on Windows. The WFP tunnel-permit presence is the
//! robust signal (absent -> present -> absent) rather than flaky traffic timing;
//! a true tunnel-egress *traffic* proof needs a peer and is folded into N4.
//!
//! Safety: `apply_firewall_killswitch` keeps an egress-allow rule that is meant
//! to keep a LAN SSH session alive, but that has never been verified on this
//! guest, so the orchestrator harness arms a guest-side dead-man's-switch
//! (schtasks firewall-restore) around this verb, and this verb installs an
//! in-process Drop guard that restores the firewall on panic. The default flow
//! never calls `block_all_egress` (which DELETES the egress-allow rule and WOULD
//! cut a LAN SSH session until rollback); that full fail-closed block is gated
//! behind the explicit `--exercise-full-block` opt-in.

use serde::Serialize;

/// Killswitch-smoke inputs. Defaults bring up the same self-only `rustynet0`
/// tunnel as the N1 tunnel-smoke, then exercise the killswitch on it.
#[derive(Debug, Clone)]
pub struct WindowsKillswitchSmokeOptions {
    pub tunnel_name: String,
    pub address: String,
    pub mesh_cidr: String,
    pub listen_port: u16,
    /// Opt-in: also exercise `block_all_egress` (full fail-closed). That removes
    /// the egress-allow rule and the WFP tunnel permit, so it WILL cut a LAN SSH
    /// session until the subsequent rollback — only safe behind the harness
    /// dead-man's-switch. Off by default so the standard run stays SSH-safe.
    pub exercise_full_block: bool,
}

impl Default for WindowsKillswitchSmokeOptions {
    fn default() -> Self {
        Self {
            tunnel_name: "rustynet0".to_owned(),
            address: "100.64.0.1/32".to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            listen_port: 51820,
            exercise_full_block: false,
        }
    }
}

/// Raw per-stage signals captured during the live exercise. Kept separate from
/// the report so the pass/fail verdict is a pure function and unit-testable
/// off-Windows.
#[derive(Debug, Clone, Default)]
pub struct WindowsKillswitchSmokeSignals {
    pub tunnel_started: bool,
    /// No stale WFP tunnel-permit before apply (clean baseline).
    pub permit_absent_before: bool,
    pub killswitch_applied: bool,
    /// `assert_killswitch` reports the killswitch active (netsh block policy +
    /// WFP permit present).
    pub asserted_active: bool,
    pub permit_present_under_killswitch: bool,
    pub rolled_back: bool,
    /// After rollback `assert_killswitch` reports inactive (expected Err).
    pub asserted_inactive_after_rollback: bool,
    pub permit_absent_after_rollback: bool,
    /// Whether the optional full fail-closed block was exercised this run.
    pub full_block_exercised: bool,
    pub full_block_applied: bool,
    /// `block_all_egress` removed the WFP tunnel permit too (the 295d780
    /// fail-OPEN fix: full block leaves no tunnel egress).
    pub full_block_permit_removed: bool,
    pub full_block_rolled_back: bool,
    pub tunnel_torn_down: bool,
}

/// Fixed-shape smoke result the orchestrator can parse.
#[derive(Debug, Clone, Serialize)]
pub struct WindowsKillswitchSmokeReport {
    pub tunnel_name: String,
    pub tunnel_started: bool,
    pub permit_absent_before: bool,
    pub killswitch_applied: bool,
    pub asserted_active: bool,
    pub permit_present_under_killswitch: bool,
    pub rolled_back: bool,
    pub asserted_inactive_after_rollback: bool,
    pub permit_absent_after_rollback: bool,
    pub full_block_exercised: bool,
    pub full_block_applied: bool,
    pub full_block_permit_removed: bool,
    pub full_block_rolled_back: bool,
    pub tunnel_torn_down: bool,
    pub overall_ok: bool,
}

impl WindowsKillswitchSmokeReport {
    /// Pure verdict so the pass/fail logic is unit-testable off-Windows. A smoke
    /// passes when the tunnel came up, the killswitch applied + asserted active
    /// with its WFP permit present, then rolled back cleanly with the permit
    /// gone and assert reporting inactive, and the tunnel was torn down. When the
    /// optional full fail-closed block was exercised, it must also have applied,
    /// removed the WFP permit, and rolled back.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn from_signals(
        options: &WindowsKillswitchSmokeOptions,
        signals: &WindowsKillswitchSmokeSignals,
    ) -> Self {
        let core_ok = signals.tunnel_started
            && signals.permit_absent_before
            && signals.killswitch_applied
            && signals.asserted_active
            && signals.permit_present_under_killswitch
            && signals.rolled_back
            && signals.asserted_inactive_after_rollback
            && signals.permit_absent_after_rollback
            && signals.tunnel_torn_down;
        let full_block_ok = if signals.full_block_exercised {
            signals.full_block_applied
                && signals.full_block_permit_removed
                && signals.full_block_rolled_back
        } else {
            true
        };
        Self {
            tunnel_name: options.tunnel_name.clone(),
            tunnel_started: signals.tunnel_started,
            permit_absent_before: signals.permit_absent_before,
            killswitch_applied: signals.killswitch_applied,
            asserted_active: signals.asserted_active,
            permit_present_under_killswitch: signals.permit_present_under_killswitch,
            rolled_back: signals.rolled_back,
            asserted_inactive_after_rollback: signals.asserted_inactive_after_rollback,
            permit_absent_after_rollback: signals.permit_absent_after_rollback,
            full_block_exercised: signals.full_block_exercised,
            full_block_applied: signals.full_block_applied,
            full_block_permit_removed: signals.full_block_permit_removed,
            full_block_rolled_back: signals.full_block_rolled_back,
            tunnel_torn_down: signals.tunnel_torn_down,
            overall_ok: core_ok && full_block_ok,
        }
    }
}

/// Bring up a single self-only tunnel, drive the killswitch through
/// apply/assert/rollback (and optionally the full fail-closed block), then tear
/// the tunnel down. The firewall is restored on every exit path: the inner
/// sequence rolls it back on success, and a Drop guard restores it on any error
/// or panic before the (cross-process) dead-man's-switch would fire.
#[cfg(windows)]
pub fn run_windows_killswitch_smoke(
    options: &WindowsKillswitchSmokeOptions,
) -> Result<WindowsKillswitchSmokeReport, String> {
    use rustynet_backend_api::{NodeId, RuntimeContext, TunnelBackend};
    use rustynet_backend_wireguard::{
        DEFAULT_WINDOWS_NETSH_EXE_PATH, DEFAULT_WINDOWS_WG_EXE_PATH,
        DEFAULT_WINDOWS_WIREGUARD_EXE_PATH, WindowsWireguardBackend,
    };

    // --- 1. Bring up a self-only tunnel (mirrors run_windows_tunnel_smoke). ---
    let (private_key, _public_key) = crate::key_material::generate_wireguard_keypair()?;
    let key_dir = std::env::temp_dir().join("rustynet-killswitch-smoke");
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
        local_node: NodeId::new("windows-killswitch-smoke")
            .map_err(|err| format!("build smoke node id failed: {err}"))?,
        interface_name: options.tunnel_name.clone(),
        mesh_cidr: options.mesh_cidr.clone(),
        local_cidr: options.address.clone(),
    };

    let start_result = backend.start(context);
    // The plaintext key is no longer needed once the (now DPAPI-sealed) config
    // has been rendered, whether or not start succeeded.
    let _ = std::fs::remove_file(key_path.as_path());
    start_result.map_err(|err| format!("tunnel bring-up failed: {err}"))?;
    let tunnel_started = backend.stats().is_ok();

    // --- 2. Build the real Windows killswitch system on the live tunnel. ---
    let egress_interface =
        crate::daemon::detect_default_egress_interface(options.tunnel_name.as_str())
            .map_err(|err| format!("egress interface auto-detect failed: {err}"))?;
    // Loopback resolver bind addr is only consulted by DNS protection (unused
    // here) but the constructor validates it must stay on loopback.
    let resolver_addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 53));
    let mut system = crate::phase10::WindowsCommandSystem::new(
        options.tunnel_name.clone(),
        egress_interface,
        resolver_addr,
    )
    .map_err(|err| format!("construct WindowsCommandSystem failed: {err:?}"))?;

    // In-process panic/error backstop: if the sequence below returns Err or
    // panics, this restores the default allow-outbound policy + removes the WFP
    // permit so the guest is never left wedged behind the killswitch.
    let mut guard = FirewallRestoreGuard::armed();
    let sequence = run_killswitch_sequence(&mut system, options, tunnel_started);

    // Always attempt teardown, regardless of the sequence outcome.
    match sequence {
        Ok(mut signals) => {
            // The sequence rolled the firewall back already; disarm the backstop.
            guard.disarm();
            signals.tunnel_torn_down = backend.shutdown().is_ok();
            if !signals.tunnel_torn_down {
                return Err("tunnel teardown failed (tunnel left up)".to_owned());
            }
            Ok(WindowsKillswitchSmokeReport::from_signals(
                options, &signals,
            ))
        }
        Err(err) => {
            // `guard` (still armed) restores the firewall on drop; best-effort
            // tunnel teardown so we do not also leak the adapter.
            let _ = backend.shutdown();
            Err(err)
        }
    }
}

/// Drive apply -> assert-active -> rollback -> assert-inactive (and optionally
/// the full fail-closed block), capturing per-stage signals. On success the
/// firewall is left rolled back; any `?` error leaves it to the caller's Drop
/// guard to restore.
#[cfg(windows)]
fn run_killswitch_sequence(
    system: &mut crate::phase10::WindowsCommandSystem,
    options: &WindowsKillswitchSmokeOptions,
    tunnel_started: bool,
) -> Result<WindowsKillswitchSmokeSignals, String> {
    use crate::phase10::DataplaneSystem;

    let mut signals = WindowsKillswitchSmokeSignals {
        tunnel_started,
        ..Default::default()
    };

    signals.permit_absent_before = !wfp_tunnel_permit_present()?;

    system
        .apply_firewall_killswitch()
        .map_err(|err| format!("apply_firewall_killswitch failed: {err:?}"))?;
    signals.killswitch_applied = true;

    // assert_killswitch is a posture *query*, not a control mutation — a failed
    // assertion is a recorded signal, not a hard error (we still roll back).
    signals.asserted_active = system.assert_killswitch().is_ok();
    signals.permit_present_under_killswitch = wfp_tunnel_permit_present()?;

    system
        .rollback_firewall()
        .map_err(|err| format!("rollback_firewall failed: {err:?}"))?;
    signals.rolled_back = true;
    signals.asserted_inactive_after_rollback = system.assert_killswitch().is_err();
    signals.permit_absent_after_rollback = !wfp_tunnel_permit_present()?;

    if options.exercise_full_block {
        signals.full_block_exercised = true;
        system
            .block_all_egress()
            .map_err(|err| format!("block_all_egress failed: {err:?}"))?;
        signals.full_block_applied = true;
        // The fail-closed proof: full block must leave NO tunnel egress permit.
        signals.full_block_permit_removed = !wfp_tunnel_permit_present()?;
        system
            .rollback_firewall()
            .map_err(|err| format!("post-block rollback_firewall failed: {err:?}"))?;
        signals.full_block_rolled_back = true;
    }

    Ok(signals)
}

#[cfg(windows)]
fn wfp_tunnel_permit_present() -> Result<bool, String> {
    rustynet_windows_native::wfp_tunnel_permit_present()
        .map_err(|err| format!("WFP tunnel-permit presence check failed: {err}"))
}

/// Restores the default allow-outbound firewall policy + removes the WFP tunnel
/// permit on drop, unless disarmed after a clean rollback. This is the
/// in-process backstop for a panic or an error mid-exercise; the orchestrator
/// harness arms a separate cross-process dead-man's-switch (schtasks) for the
/// case where this process is hard-killed (which bypasses Drop).
#[cfg(windows)]
struct FirewallRestoreGuard {
    armed: bool,
}

#[cfg(windows)]
impl FirewallRestoreGuard {
    fn armed() -> Self {
        Self { armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(windows)]
impl Drop for FirewallRestoreGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = rustynet_windows_native::remove_wfp_tunnel_permit();
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "set",
                "allprofiles",
                "firewallpolicy",
                "allowinbound,allowoutbound",
            ])
            .output();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_core_true() -> WindowsKillswitchSmokeSignals {
        WindowsKillswitchSmokeSignals {
            tunnel_started: true,
            permit_absent_before: true,
            killswitch_applied: true,
            asserted_active: true,
            permit_present_under_killswitch: true,
            rolled_back: true,
            asserted_inactive_after_rollback: true,
            permit_absent_after_rollback: true,
            tunnel_torn_down: true,
            ..Default::default()
        }
    }

    #[test]
    fn passes_when_all_core_signals_true_and_no_full_block() {
        let report = WindowsKillswitchSmokeReport::from_signals(
            &WindowsKillswitchSmokeOptions::default(),
            &all_core_true(),
        );
        assert!(report.overall_ok);
        assert!(!report.full_block_exercised);
    }

    #[test]
    fn fails_when_permit_still_present_after_rollback() {
        let mut signals = all_core_true();
        signals.permit_absent_after_rollback = false;
        let report = WindowsKillswitchSmokeReport::from_signals(
            &WindowsKillswitchSmokeOptions::default(),
            &signals,
        );
        assert!(
            !report.overall_ok,
            "a WFP permit left in place after rollback is a leak and must fail"
        );
    }

    #[test]
    fn fails_when_assert_did_not_report_active() {
        let mut signals = all_core_true();
        signals.asserted_active = false;
        let report = WindowsKillswitchSmokeReport::from_signals(
            &WindowsKillswitchSmokeOptions::default(),
            &signals,
        );
        assert!(!report.overall_ok);
    }

    #[test]
    fn full_block_run_requires_permit_removed() {
        // Exercised full block but the permit was NOT removed = fail OPEN = fail.
        let mut signals = all_core_true();
        signals.full_block_exercised = true;
        signals.full_block_applied = true;
        signals.full_block_permit_removed = false;
        signals.full_block_rolled_back = true;
        let report = WindowsKillswitchSmokeReport::from_signals(
            &WindowsKillswitchSmokeOptions::default(),
            &signals,
        );
        assert!(
            !report.overall_ok,
            "block_all_egress that leaves the WFP permit in place fails OPEN and must fail"
        );
    }

    #[test]
    fn full_block_run_passes_when_permit_removed_and_rolled_back() {
        let mut signals = all_core_true();
        signals.full_block_exercised = true;
        signals.full_block_applied = true;
        signals.full_block_permit_removed = true;
        signals.full_block_rolled_back = true;
        let report = WindowsKillswitchSmokeReport::from_signals(
            &WindowsKillswitchSmokeOptions::default(),
            &signals,
        );
        assert!(report.overall_ok);
        assert!(report.full_block_exercised);
    }
}
