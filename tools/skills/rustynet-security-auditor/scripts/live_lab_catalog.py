#!/usr/bin/env python3
"""Shared Rustynet live-lab validation catalog for the network-adversarial-hardening skill."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckMetadata:
    severity: str
    title: str
    rationale: str


@dataclass(frozen=True)
class ValidationSpec:
    key: str
    mode: str
    title: str
    exploit_family: str
    script_path: str
    default_report_name: str
    coverage_targets: tuple[str, ...]
    required_args: tuple[str, ...]
    supported_args: tuple[str, ...]
    required_report_fields: tuple[str, ...]
    required_check_keys: tuple[str, ...]
    affected_files: tuple[str, ...]
    check_metadata: dict[str, CheckMetadata]
    unknown_failure_title: str


LIVE_VALIDATIONS: dict[str, ValidationSpec] = {
    "control_surface_exposure": ValidationSpec(
        key="control_surface_exposure",
        mode="live_linux_control_surface_exposure",
        title="Local control surface exposure",
        exploit_family="local-socket-spoofing",
        script_path="scripts/e2e/live_linux_control_surface_exposure_test.sh",
        default_report_name="live_linux_control_surface_exposure_report.json",
        coverage_targets=("Tailscale TS-2022-005",),
        required_args=("client_host",),
        supported_args=(
            "exit_host",
            "client_host",
            "entry_host",
            "aux_host",
            "extra_host",
            "probe_host",
            "dns_bind_addr",
        ),
        required_report_fields=(
            "phase",
            "mode",
            "evidence_mode",
            "captured_at",
            "captured_at_unix",
            "status",
            "checks",
            "hosts",
            "evidence",
            "dns_bind_addr",
        ),
        required_check_keys=(
            "all_daemon_sockets_secure",
            "all_helper_sockets_secure",
            "no_rustynet_tcp_listeners",
            "rustynet_udp_loopback_only",
            "remote_underlay_dns_probe_blocked",
        ),
        affected_files=(
            "crates/rustynet-cli/src/main.rs",
            "crates/rustynetd/src/privileged_helper.rs",
            "crates/rustynetd/src/daemon.rs",
        ),
        check_metadata={
            "all_daemon_sockets_secure": CheckMetadata(
                severity="critical",
                title="Daemon socket custody weakened",
                rationale="An insecure daemon socket can let an untrusted local principal impersonate the control surface.",
            ),
            "all_helper_sockets_secure": CheckMetadata(
                severity="critical",
                title="Privileged helper socket custody weakened",
                rationale="An insecure privileged helper socket can expose root-adjacent operations to an attacker on the host.",
            ),
            "no_rustynet_tcp_listeners": CheckMetadata(
                severity="critical",
                title="Unexpected TCP control listener exposed",
                rationale="A browser-reachable or peer-reachable TCP listener widens the attack surface toward rebinding and unauthenticated probing classes.",
            ),
            "rustynet_udp_loopback_only": CheckMetadata(
                severity="high",
                title="Managed DNS listener exposed beyond loopback",
                rationale="The authoritative resolver must remain loopback-only or peers may query or abuse managed DNS directly.",
            ),
            "remote_underlay_dns_probe_blocked": CheckMetadata(
                severity="high",
                title="Peer underlay reached the managed DNS listener",
                rationale="If a peer can query the authoritative resolver over underlay, managed DNS is no longer isolated to the local host.",
            ),
        },
        unknown_failure_title="Control surface exposure report failed",
    ),
    "server_ip_bypass": ValidationSpec(
        key="server_ip_bypass",
        mode="live_linux_server_ip_bypass",
        title="Server-IP and local-network bypass scoping",
        exploit_family="route-hijack",
        script_path="scripts/e2e/live_linux_server_ip_bypass_test.sh",
        default_report_name="live_linux_server_ip_bypass_report.json",
        coverage_targets=("WireGuard-based clients TunnelCrack",),
        required_args=("client_host", "probe_host"),
        supported_args=(
            "client_host",
            "probe_host",
            "ssh_allow_cidrs",
            "probe_port",
        ),
        required_report_fields=(
            "phase",
            "mode",
            "evidence_mode",
            "captured_at",
            "captured_at_unix",
            "status",
            "checks",
            "evidence",
            "probe_host_ip",
            "probe_port",
        ),
        required_check_keys=(
            "internet_route_via_rustynet0",
            "probe_host_self_service_reachable",
            "probe_endpoint_route_direct_not_tunnelled",
            "probe_service_blocked_from_client",
            "no_unexpected_bypass_routes",
        ),
        affected_files=(
            "crates/rustynetd/src/phase10.rs",
            "crates/rustynetd/src/dataplane.rs",
            "crates/rustynet-backend-wireguard/src/lib.rs",
        ),
        check_metadata={
            "internet_route_via_rustynet0": CheckMetadata(
                severity="critical",
                title="Protected internet route bypassed tunnel",
                rationale="If the default route no longer prefers rustynet0, protected traffic may leak outside the mesh.",
            ),
            "probe_host_self_service_reachable": CheckMetadata(
                severity="medium",
                title="Probe host did not serve the expected underlay endpoint",
                rationale="The test environment may be invalid; confirm the probe service came up before trusting the rest of the result.",
            ),
            "probe_endpoint_route_direct_not_tunnelled": CheckMetadata(
                severity="high",
                title="Peer endpoint bypass route not tightly scoped",
                rationale="Endpoint reachability should be direct and explicit, not tunnelled through broad fallback routing.",
            ),
            "probe_service_blocked_from_client": CheckMetadata(
                severity="critical",
                title="Client reached forbidden underlay service over bypass path",
                rationale="This is the direct TunnelCrack-style failure: management or endpoint bypass widened into general service reachability.",
            ),
            "no_unexpected_bypass_routes": CheckMetadata(
                severity="critical",
                title="Unexpected bypass routes present in protected table",
                rationale="Broad bypass routes create unbounded leak paths for traffic that should stay inside the tunnel policy.",
            ),
        },
        unknown_failure_title="Server-IP bypass report failed",
    ),
    "endpoint_hijack": ValidationSpec(
        key="endpoint_hijack",
        mode="live_linux_endpoint_hijack",
        title="Endpoint hijack and traversal fail-closed behavior",
        exploit_family="traversal-abuse",
        script_path="scripts/e2e/live_linux_endpoint_hijack_test.sh",
        default_report_name="live_linux_endpoint_hijack_report.json",
        coverage_targets=("WireGuard Known Limitations & Tradeoffs",),
        required_args=("client_host", "rogue_endpoint_ip"),
        supported_args=(
            "client_host",
            "rogue_endpoint_ip",
            "socket_path",
            "assignment_path",
        ),
        required_report_fields=(
            "phase",
            "mode",
            "evidence_mode",
            "captured_at",
            "captured_at_unix",
            "status",
            "checks",
            "evidence",
            "rogue_endpoint_ip",
        ),
        required_check_keys=(
            "baseline_runtime_secure",
            "hijack_drives_fail_closed",
            "restricted_safe_mode_engaged",
            "netcheck_reports_fail_closed",
            "rogue_endpoint_not_adopted",
            "recovery_restores_secure_runtime",
            "recovery_keeps_rogue_endpoint_rejected",
        ),
        affected_files=(
            "crates/rustynetd/src/daemon.rs",
            "crates/rustynetd/src/traversal.rs",
            "crates/rustynetd/src/phase10.rs",
        ),
        check_metadata={
            "baseline_runtime_secure": CheckMetadata(
                severity="medium",
                title="Baseline runtime was not in a secure state before hijack test",
                rationale="The hijack test cannot be trusted if the node already started from fail-closed or otherwise degraded runtime state.",
            ),
            "hijack_drives_fail_closed": CheckMetadata(
                severity="critical",
                title="Tampered endpoint assignment did not drive fail-closed behavior",
                rationale="A signed-state endpoint hijack must push runtime into fail-closed rather than allowing mutated path adoption.",
            ),
            "restricted_safe_mode_engaged": CheckMetadata(
                severity="high",
                title="Restricted safe mode did not engage on endpoint hijack",
                rationale="The daemon should make the trust failure explicit and restrictive when traversal or assignment integrity is violated.",
            ),
            "netcheck_reports_fail_closed": CheckMetadata(
                severity="high",
                title="Netcheck did not surface fail-closed traversal state",
                rationale="Operators must see the traversal integrity failure directly in diagnostics or they cannot distinguish secure denial from random breakage.",
            ),
            "rogue_endpoint_not_adopted": CheckMetadata(
                severity="critical",
                title="Rogue endpoint was adopted after assignment tamper",
                rationale="Adopting a forged endpoint defeats the signed traversal and assignment trust model.",
            ),
            "recovery_restores_secure_runtime": CheckMetadata(
                severity="high",
                title="Runtime did not recover cleanly after restoring trusted assignment",
                rationale="Recovery must be deterministic and not leave the node stuck in a weakened or ambiguous state.",
            ),
            "recovery_keeps_rogue_endpoint_rejected": CheckMetadata(
                severity="critical",
                title="Rogue endpoint persisted after recovery",
                rationale="If the rogue endpoint survives restoration, the trust boundary is still broken after nominal recovery.",
            ),
        },
        unknown_failure_title="Endpoint hijack report failed",
    ),
}

MODE_INDEX = {spec.mode: spec for spec in LIVE_VALIDATIONS.values()}
