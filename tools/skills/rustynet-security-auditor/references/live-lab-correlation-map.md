# Rustynet Live-Lab Correlation Map

Use this reference when a live validation report fails and the skill needs to move quickly from runtime evidence to likely enforcement points.

## Control Surface Exposure

- Validation key: `control_surface_exposure`
- Report mode: `live_linux_control_surface_exposure`
- Historical analog:
  - Tailscale `TS-2022-005`
- Primary exploit family:
  - `local-socket-spoofing`
- Rustynet validator:
  - `scripts/e2e/live_linux_control_surface_exposure_test.sh`
- Likely enforcement points:
  - `crates/rustynet-cli/src/main.rs`
  - `crates/rustynetd/src/privileged_helper.rs`
  - `crates/rustynetd/src/daemon.rs`
- Key failure meanings:
  - `all_daemon_sockets_secure`
    - daemon socket ownership, mode, or type checks weakened
  - `all_helper_sockets_secure`
    - privileged helper socket custody weakened
  - `no_rustynet_tcp_listeners`
    - browser- or peer-reachable control listener exposed
  - `rustynet_udp_loopback_only`
    - managed DNS listener bound beyond loopback
  - `remote_underlay_dns_probe_blocked`
    - peer underlay could query managed DNS directly

## Server-IP And Local-Network Bypass

- Validation key: `server_ip_bypass`
- Report mode: `live_linux_server_ip_bypass`
- Historical analog:
  - TunnelCrack
- Primary exploit family:
  - `route-hijack`
- Rustynet validator:
  - `scripts/e2e/live_linux_server_ip_bypass_test.sh`
- Likely enforcement points:
  - `crates/rustynetd/src/phase10.rs`
  - `crates/rustynetd/src/dataplane.rs`
  - `crates/rustynet-backend-wireguard/src/lib.rs`
- Key failure meanings:
  - `internet_route_via_rustynet0`
    - protected internet route bypassed the tunnel
  - `probe_endpoint_route_direct_not_tunnelled`
    - peer endpoint bypass route is wrong or overly broad
  - `probe_service_blocked_from_client`
    - endpoint or management bypass widened into real service reachability
  - `no_unexpected_bypass_routes`
    - extra bypass routes created broader leak surface

## Endpoint Hijack And Traversal Fail-Closed

- Validation key: `endpoint_hijack`
- Report mode: `live_linux_endpoint_hijack`
- Historical analog:
  - WireGuard host-integration / endpoint-mobility risk class
- Primary exploit family:
  - `traversal-abuse`
- Rustynet validator:
  - `scripts/e2e/live_linux_endpoint_hijack_test.sh`
- Likely enforcement points:
  - `crates/rustynetd/src/daemon.rs`
  - `crates/rustynetd/src/traversal.rs`
  - `crates/rustynetd/src/phase10.rs`
- Key failure meanings:
  - `hijack_drives_fail_closed`
    - tampered endpoint assignment did not force secure denial
  - `restricted_safe_mode_engaged`
    - runtime trust failure was not made explicitly restrictive
  - `netcheck_reports_fail_closed`
    - operator diagnostics do not surface traversal integrity loss
  - `rogue_endpoint_not_adopted`
    - forged endpoint was accepted into runtime state
  - `recovery_restores_secure_runtime`
    - restore path is incomplete or non-deterministic
  - `recovery_keeps_rogue_endpoint_rejected`
    - rogue endpoint survived trusted-state restoration
