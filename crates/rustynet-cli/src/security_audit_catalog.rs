#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy)]
pub struct CheckMetadata {
    pub severity: &'static str,
    pub title: &'static str,
    pub rationale: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct CheckMetadataEntry {
    pub key: &'static str,
    pub metadata: CheckMetadata,
}

#[derive(Debug, Clone, Copy)]
pub struct ValidationSpec {
    pub key: &'static str,
    pub mode: &'static str,
    pub title: &'static str,
    pub exploit_family: &'static str,
    pub script_path: &'static str,
    pub default_report_name: &'static str,
    pub coverage_targets: &'static [&'static str],
    pub required_args: &'static [&'static str],
    pub supported_args: &'static [&'static str],
    pub required_report_fields: &'static [&'static str],
    pub required_check_keys: &'static [&'static str],
    pub affected_files: &'static [&'static str],
    pub check_metadata: &'static [CheckMetadataEntry],
    pub unknown_failure_title: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct ComparativeCommandSpec {
    pub key: &'static str,
    pub label: &'static str,
    pub argv: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct ComparativeCatalogEntry {
    pub project: &'static str,
    pub incident: &'static str,
    pub date: &'static str,
    pub exploit_class: &'static str,
    pub summary: &'static str,
    pub rustynet_analog: &'static str,
    pub attack_family: &'static str,
    pub coverage_status: &'static str,
    pub command_keys: &'static [&'static str],
    pub live_validation_scripts: &'static [&'static str],
    pub expected_secure_result: &'static str,
    pub sources: &'static [&'static str],
}

const CONTROL_SURFACE_EXPOSURE_CHECKS: &[CheckMetadataEntry] = &[
    CheckMetadataEntry {
        key: "all_daemon_sockets_secure",
        metadata: CheckMetadata {
            severity: "critical",
            title: "Daemon socket custody weakened",
            rationale: "An insecure daemon socket can let an untrusted local principal impersonate the control surface.",
        },
    },
    CheckMetadataEntry {
        key: "all_helper_sockets_secure",
        metadata: CheckMetadata {
            severity: "critical",
            title: "Privileged helper socket custody weakened",
            rationale: "An insecure privileged helper socket can expose root-adjacent operations to an attacker on the host.",
        },
    },
    CheckMetadataEntry {
        key: "no_rustynet_tcp_listeners",
        metadata: CheckMetadata {
            severity: "critical",
            title: "Unexpected TCP control listener exposed",
            rationale: "A browser-reachable or peer-reachable TCP listener widens the attack surface toward rebinding and unauthenticated probing classes.",
        },
    },
    CheckMetadataEntry {
        key: "rustynet_udp_loopback_only",
        metadata: CheckMetadata {
            severity: "high",
            title: "Managed DNS listener exposed beyond loopback",
            rationale: "The authoritative resolver must remain loopback-only or peers may query or abuse managed DNS directly.",
        },
    },
    CheckMetadataEntry {
        key: "remote_underlay_dns_probe_blocked",
        metadata: CheckMetadata {
            severity: "high",
            title: "Peer underlay reached the managed DNS listener",
            rationale: "If a peer can query the authoritative resolver over underlay, managed DNS is no longer isolated to the local host.",
        },
    },
];

const SERVER_IP_BYPASS_CHECKS: &[CheckMetadataEntry] = &[
    CheckMetadataEntry {
        key: "internet_route_via_rustynet0",
        metadata: CheckMetadata {
            severity: "critical",
            title: "Protected internet route bypassed tunnel",
            rationale: "If the default route no longer prefers rustynet0, protected traffic may leak outside the mesh.",
        },
    },
    CheckMetadataEntry {
        key: "probe_host_self_service_reachable",
        metadata: CheckMetadata {
            severity: "medium",
            title: "Probe host did not serve the expected underlay endpoint",
            rationale: "The test environment may be invalid; confirm the probe service came up before trusting the rest of the result.",
        },
    },
    CheckMetadataEntry {
        key: "probe_endpoint_route_direct_not_tunnelled",
        metadata: CheckMetadata {
            severity: "high",
            title: "Peer endpoint bypass route not tightly scoped",
            rationale: "Endpoint reachability should be direct and explicit, not tunnelled through broad fallback routing.",
        },
    },
    CheckMetadataEntry {
        key: "probe_service_blocked_from_client",
        metadata: CheckMetadata {
            severity: "critical",
            title: "Client reached forbidden underlay service over bypass path",
            rationale: "This is the direct TunnelCrack-style failure: management or endpoint bypass widened into general service reachability.",
        },
    },
    CheckMetadataEntry {
        key: "no_unexpected_bypass_routes",
        metadata: CheckMetadata {
            severity: "critical",
            title: "Unexpected bypass routes present in protected table",
            rationale: "Broad bypass routes create unbounded leak paths for traffic that should stay inside the tunnel policy.",
        },
    },
];

const ENDPOINT_HIJACK_CHECKS: &[CheckMetadataEntry] = &[
    CheckMetadataEntry {
        key: "baseline_runtime_secure",
        metadata: CheckMetadata {
            severity: "medium",
            title: "Baseline runtime was not in a secure state before hijack test",
            rationale: "The hijack test cannot be trusted if the node already started from fail-closed or otherwise degraded runtime state.",
        },
    },
    CheckMetadataEntry {
        key: "hijack_drives_fail_closed",
        metadata: CheckMetadata {
            severity: "critical",
            title: "Tampered endpoint assignment did not drive fail-closed behavior",
            rationale: "A signed-state endpoint hijack must push runtime into fail-closed rather than allowing mutated path adoption.",
        },
    },
    CheckMetadataEntry {
        key: "restricted_safe_mode_engaged",
        metadata: CheckMetadata {
            severity: "high",
            title: "Restricted safe mode did not engage on endpoint hijack",
            rationale: "The daemon should make the trust failure explicit and restrictive when traversal or assignment integrity is violated.",
        },
    },
    CheckMetadataEntry {
        key: "netcheck_reports_fail_closed",
        metadata: CheckMetadata {
            severity: "high",
            title: "Netcheck did not surface fail-closed traversal state",
            rationale: "Operators must see the traversal integrity failure directly in diagnostics or they cannot distinguish secure denial from random breakage.",
        },
    },
    CheckMetadataEntry {
        key: "rogue_endpoint_not_adopted",
        metadata: CheckMetadata {
            severity: "critical",
            title: "Rogue endpoint was adopted after assignment tamper",
            rationale: "Adopting a forged endpoint defeats the signed traversal and assignment trust model.",
        },
    },
    CheckMetadataEntry {
        key: "recovery_restores_secure_runtime",
        metadata: CheckMetadata {
            severity: "high",
            title: "Runtime did not recover cleanly after restoring trusted assignment",
            rationale: "Recovery must be deterministic and not leave the node stuck in a weakened or ambiguous state.",
        },
    },
    CheckMetadataEntry {
        key: "recovery_keeps_rogue_endpoint_rejected",
        metadata: CheckMetadata {
            severity: "critical",
            title: "Rogue endpoint persisted after recovery",
            rationale: "If the rogue endpoint survives restoration, the trust boundary is still broken after nominal recovery.",
        },
    },
];

pub const LIVE_VALIDATION_SPECS: &[ValidationSpec] = &[
    ValidationSpec {
        key: "control_surface_exposure",
        mode: "live_linux_control_surface_exposure",
        title: "Local control surface exposure",
        exploit_family: "local-socket-spoofing",
        script_path: "scripts/e2e/live_linux_control_surface_exposure_test.sh",
        default_report_name: "live_linux_control_surface_exposure_report.json",
        coverage_targets: &["Tailscale TS-2022-005"],
        required_args: &["client_host"],
        supported_args: &[
            "exit_host",
            "client_host",
            "entry_host",
            "aux_host",
            "extra_host",
            "probe_host",
            "dns_bind_addr",
        ],
        required_report_fields: &[
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
        ],
        required_check_keys: &[
            "all_daemon_sockets_secure",
            "all_helper_sockets_secure",
            "no_rustynet_tcp_listeners",
            "rustynet_udp_loopback_only",
            "remote_underlay_dns_probe_blocked",
        ],
        affected_files: &[
            "crates/rustynet-cli/src/main.rs",
            "crates/rustynetd/src/privileged_helper.rs",
            "crates/rustynetd/src/daemon.rs",
        ],
        check_metadata: CONTROL_SURFACE_EXPOSURE_CHECKS,
        unknown_failure_title: "Control surface exposure report failed",
    },
    ValidationSpec {
        key: "server_ip_bypass",
        mode: "live_linux_server_ip_bypass",
        title: "Server-IP and local-network bypass scoping",
        exploit_family: "route-hijack",
        script_path: "scripts/e2e/live_linux_server_ip_bypass_test.sh",
        default_report_name: "live_linux_server_ip_bypass_report.json",
        coverage_targets: &["WireGuard-based clients TunnelCrack"],
        required_args: &["client_host", "probe_host"],
        supported_args: &["client_host", "probe_host", "ssh_allow_cidrs", "probe_port"],
        required_report_fields: &[
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
        ],
        required_check_keys: &[
            "internet_route_via_rustynet0",
            "probe_host_self_service_reachable",
            "probe_endpoint_route_direct_not_tunnelled",
            "probe_service_blocked_from_client",
            "no_unexpected_bypass_routes",
        ],
        affected_files: &[
            "crates/rustynetd/src/phase10.rs",
            "crates/rustynetd/src/dataplane.rs",
            "crates/rustynet-backend-wireguard/src/lib.rs",
        ],
        check_metadata: SERVER_IP_BYPASS_CHECKS,
        unknown_failure_title: "Server-IP bypass report failed",
    },
    ValidationSpec {
        key: "endpoint_hijack",
        mode: "live_linux_endpoint_hijack",
        title: "Endpoint hijack and traversal fail-closed behavior",
        exploit_family: "traversal-abuse",
        script_path: "scripts/e2e/live_linux_endpoint_hijack_test.sh",
        default_report_name: "live_linux_endpoint_hijack_report.json",
        coverage_targets: &["WireGuard Known Limitations & Tradeoffs"],
        required_args: &["client_host", "rogue_endpoint_ip"],
        supported_args: &[
            "client_host",
            "rogue_endpoint_ip",
            "socket_path",
            "assignment_path",
        ],
        required_report_fields: &[
            "phase",
            "mode",
            "evidence_mode",
            "captured_at",
            "captured_at_unix",
            "status",
            "checks",
            "evidence",
            "rogue_endpoint_ip",
        ],
        required_check_keys: &[
            "baseline_runtime_secure",
            "hijack_drives_fail_closed",
            "restricted_safe_mode_engaged",
            "netcheck_reports_fail_closed",
            "rogue_endpoint_not_adopted",
            "recovery_restores_secure_runtime",
            "recovery_keeps_rogue_endpoint_rejected",
        ],
        affected_files: &[
            "crates/rustynetd/src/daemon.rs",
            "crates/rustynetd/src/traversal.rs",
            "crates/rustynetd/src/phase10.rs",
        ],
        check_metadata: ENDPOINT_HIJACK_CHECKS,
        unknown_failure_title: "Endpoint hijack report failed",
    },
];

pub const VALIDATION_ARG_FLAGS: &[(&str, &str)] = &[
    ("exit_host", "--exit-host"),
    ("client_host", "--client-host"),
    ("entry_host", "--entry-host"),
    ("aux_host", "--aux-host"),
    ("extra_host", "--extra-host"),
    ("probe_host", "--probe-host"),
    ("dns_bind_addr", "--dns-bind-addr"),
    ("ssh_allow_cidrs", "--ssh-allow-cidrs"),
    ("probe_port", "--probe-port"),
    ("rogue_endpoint_ip", "--rogue-endpoint-ip"),
    ("socket_path", "--socket-path"),
    ("assignment_path", "--assignment-path"),
];

pub const COMPARATIVE_COMMAND_SPECS: &[ComparativeCommandSpec] = &[
    ComparativeCommandSpec {
        key: "control_socket_validator",
        label: "CLI daemon-socket trust validation",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynet-cli",
            "control_socket_validator",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "helper_arg_count",
        label: "Privileged helper rejects too many arguments",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "privileged_helper::tests::validate_request_rejects_too_many_arguments",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "helper_arg_size",
        label: "Privileged helper rejects oversized arguments",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "privileged_helper::tests::validate_request_rejects_argument_over_max_bytes",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "helper_shell_metacharacters",
        label: "Privileged helper rejects shell metacharacters",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "privileged_helper::tests::fuzzgate_rejects_unknown_tokens_and_shell_metacharacters",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "helper_no_shell_construction",
        label: "Admin helper validation rejects shell construction",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynet-control",
            "admin::tests::privileged_helper_validation_rejects_shell_construction",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "phase4_fail_closed",
        label: "Dataplane fail-closed tunnel and DNS behavior",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "dataplane::tests::phase4_fail_close_blocks_tunnel_and_dns_when_required",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "phase10_exit_nat",
        label: "Exit serving requires NAT/forwarding",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "phase10::tests::apply_exit_serving_requires_nat_forwarding",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "route_mgmt_bypass_ipv4",
        label: "Management bypass route scoping for IPv4",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "phase10::tests::management_bypass_route_args_use_ipv4_routing_for_ipv4_cidr",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "route_peer_bypass_ipv4",
        label: "Peer endpoint bypass host-route scoping for IPv4",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "phase10::tests::peer_endpoint_bypass_route_args_use_ipv4_host_route",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "dns_servfail_missing_zone",
        label: "Managed DNS SERVFAIL when signed zone is missing",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "dns_resolver_servfails_managed_name_when_zone_is_missing",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "dns_refuse_non_managed",
        label: "Managed resolver refuses non-managed names",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "dns_resolver_refuses_non_managed_name",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "dns_ip_crosscheck",
        label: "DNS bundle rejects record IP outside assignment",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "load_dns_zone_bundle_rejects_record_ip_outside_assignment",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "role_blocks_admin",
        label: "Client role blocks admin mutations",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "daemon_runtime_client_role_blocks_admin_mutations",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "revoked_exit_denied",
        label: "Revoked membership node denied as exit",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "daemon_runtime_denies_exit_selection_for_revoked_membership_node",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "policy_denies_unknown",
        label: "Policy denies revoked and unknown nodes",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynet-policy",
            "membership_aware_contextual_policy_denies_revoked_and_unknown_nodes",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "policy_preserves_protocol_filters",
        label: "Policy preserves protocol filters",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynet-policy",
            "membership_aware_policy_preserves_protocol_filters",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "policy_shared_exit_protocol_filters",
        label: "Shared-exit context preserves protocol filters",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynet-policy",
            "protocol_filter_is_preserved_for_shared_exit_context",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "redaction_structured_logs",
        label: "Structured logger never writes cleartext secrets",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynet-control",
            "operations::tests::structured_logger_never_writes_cleartext_secrets",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "redaction_ingestion_paths",
        label: "Redaction covers all ingestion paths",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynet-control",
            "operations::tests::redaction_covers_all_ingestion_paths",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "throwaway_single_use",
        label: "Throwaway credentials stay single-use under concurrency",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynet-control",
            "throwaway_credential_atomic_single_use_under_concurrency",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "restricted_safe_mode_without_trust",
        label: "Runtime enters restricted safe mode without trust evidence",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "daemon::tests::daemon_runtime_enters_restricted_safe_mode_without_trust_evidence",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "present_bundle_requires_verifier",
        label: "Preflight rejects traversal bundle without verifier key",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "daemon::tests::preflight_rejects_present_traversal_bundle_when_verifier_key_missing",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "traversal_tamper_replay",
        label: "Traversal bundle rejects tampering and replay",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "daemon::tests::load_traversal_bundle_rejects_tampered_signature_and_replay",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "traversal_wrong_signer",
        label: "Traversal adversarial gate rejects stale, forged, and replayed hints",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "traversal_netcheck_fail_closed",
        label: "Netcheck rejects forged traversal hints",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "traversal_nat_mismatch",
        label: "Traversal gate blocks unauthorized direct path and keeps relay fallback",
        argv: &[
            "cargo",
            "test",
            "-p",
            "rustynetd",
            "traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback",
            "--",
            "--nocapture",
        ],
    },
    ComparativeCommandSpec {
        key: "constant_time_backlog",
        label: "HP3 constant-time backlog marker",
        argv: &[
            "rg",
            "-n",
            "constant-time auth/token checks",
            "documents/operations/SecurityHardeningBacklog_2026-03-09.md",
        ],
    },
];

pub const COMPARATIVE_STATUS_ORDER: &[(&str, usize)] = &[
    ("covered", 0),
    ("partially_covered", 1),
    ("architecturally_not_applicable", 2),
    ("future_surface_gap", 3),
];

pub const COMPARATIVE_CATALOG: &[ComparativeCatalogEntry] = &[
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2022-004",
        date: "2022",
        exploit_class: "Local API DNS rebinding",
        summary: "Browser-originated DNS rebinding could reach a localhost control API and trigger local command execution.",
        rustynet_analog: "Local control surface spoofing and privileged-boundary hardening.",
        attack_family: "local-socket-spoofing",
        coverage_status: "covered",
        command_keys: &[
            "control_socket_validator",
            "helper_shell_metacharacters",
            "helper_no_shell_construction",
        ],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet rejects insecure local control surfaces before connecting and never shells untrusted helper input.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2022-005",
        date: "2022",
        exploit_class: "Peer API DNS rebinding",
        summary: "Browser-originated requests could reach a peer API and expose local env or response data.",
        rustynet_analog: "No browser-reachable peer control API, plus socket trust validation and secret redaction.",
        attack_family: "local-socket-spoofing",
        coverage_status: "partially_covered",
        command_keys: &[
            "control_socket_validator",
            "redaction_structured_logs",
            "redaction_ingestion_paths",
        ],
        live_validation_scripts: &["scripts/e2e/live_linux_control_surface_exposure_test.sh"],
        expected_secure_result: "Rustynet keeps the control plane off localhost HTTP surfaces and redacts secret-bearing output paths.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2024-005",
        date: "2024",
        exploit_class: "Insufficient inbound packet filtering on exit or subnet nodes",
        summary: "Linux exit-node or routed modes did not filter inbound traffic tightly enough.",
        rustynet_analog: "Exit-serving must keep fail-closed packet filtering and forwarding constraints.",
        attack_family: "route-hijack",
        coverage_status: "covered",
        command_keys: &["phase4_fail_closed", "phase10_exit_nat"],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet blocks tunnel or DNS leakage and refuses exit-serving without required NAT/forwarding policy.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2024-007",
        date: "2024",
        exploit_class: "Split-DNS namespace handling bug",
        summary: "Special-domain handling under split DNS could yield unsafe resolver behavior.",
        rustynet_analog: "Managed DNS namespace integrity with refuse-or-servfail semantics.",
        attack_family: "dns-integrity",
        coverage_status: "covered",
        command_keys: &[
            "dns_servfail_missing_zone",
            "dns_refuse_non_managed",
            "dns_ip_crosscheck",
        ],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet SERVFAILs managed names when signed state is bad and refuses non-managed names instead of guessing or forwarding.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2025-002",
        date: "2025",
        exploit_class: "Header spoofing against local file-transfer auth",
        summary: "A trusted local HTTP header could be spoofed to bypass authorization.",
        rustynet_analog: "Avoid spoofable local HTTP auth surfaces; rely on Unix sockets and OS identity instead.",
        attack_family: "local-socket-spoofing",
        coverage_status: "architecturally_not_applicable",
        command_keys: &[
            "control_socket_validator",
            "helper_arg_count",
            "helper_arg_size",
        ],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet keeps local privilege-sensitive control on pinned Unix sockets and strict request schemas, not trustable HTTP headers.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2025-003",
        date: "2025",
        exploit_class: "Non-constant-time relay auth comparison",
        summary: "Relay auth secrets were compared in a timing-sensitive way.",
        rustynet_analog: "Future HP3 relay auth tokens or MACs must use constant-time comparison.",
        attack_family: "traversal-abuse",
        coverage_status: "future_surface_gap",
        command_keys: &["constant_time_backlog"],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet must not ship relay auth without explicit constant-time checks and dedicated regression coverage.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2025-004",
        date: "2025",
        exploit_class: "Tenant trust flaw through shared public email domains",
        summary: "Authorization trusted a shared public email-domain assumption too broadly.",
        rustynet_analog: "Signed node identity and membership authorization must deny unknown or revoked principals.",
        attack_family: "missing-state-fail-closed",
        coverage_status: "covered",
        command_keys: &["policy_denies_unknown", "revoked_exit_denied"],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet authorizes by signed node identity and current membership state, not weak shared-domain assumptions.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2025-005",
        date: "2025",
        exploit_class: "Auth key or secret logging",
        summary: "Auth keys could be logged in plaintext.",
        rustynet_analog: "Secret redaction across structured logs, debug output, and operational flows.",
        attack_family: "secret-custody",
        coverage_status: "covered",
        command_keys: &["redaction_structured_logs", "redaction_ingestion_paths"],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet logs remain redacted across all ingestion paths and debug surfaces.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2025-006",
        date: "2025",
        exploit_class: "Protocol-filter omission in granted access paths",
        summary: "Authorization paths could omit protocol restrictions and widen access.",
        rustynet_analog: "Membership-aware policy must preserve protocol filters across contextual and shared-exit evaluation.",
        attack_family: "route-hijack",
        coverage_status: "covered",
        command_keys: &[
            "policy_preserves_protocol_filters",
            "policy_shared_exit_protocol_filters",
        ],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet keeps protocol filters intact through every policy path.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2025-007",
        date: "2025",
        exploit_class: "One-off auth key reuse race",
        summary: "Concurrent requests could reuse one-off auth keys.",
        rustynet_analog: "Throwaway enrollment credentials must stay single-use under concurrency.",
        attack_family: "control-plane-replay",
        coverage_status: "covered",
        command_keys: &["throwaway_single_use"],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet single-use credentials remain atomic under concurrency.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2025-008",
        date: "2025",
        exploit_class: "Missing-state fail-open in trusted-state enforcement",
        summary: "A lock or trust mechanism could be bypassed when its state directory was missing.",
        rustynet_analog: "Missing signed state or verifier keys must force restricted safe mode or hard failure.",
        attack_family: "missing-state-fail-closed",
        coverage_status: "covered",
        command_keys: &[
            "restricted_safe_mode_without_trust",
            "present_bundle_requires_verifier",
        ],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet does not silently continue when trust-critical state disappears.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "Tailscale",
        incident: "TS-2026-001",
        date: "2026",
        exploit_class: "Shell injection to root command execution",
        summary: "Shell construction allowed arbitrary root command execution.",
        rustynet_analog: "Privileged helper boundary must remain argv-only with strict schema validation.",
        attack_family: "helper-input-abuse",
        coverage_status: "covered",
        command_keys: &[
            "helper_no_shell_construction",
            "helper_shell_metacharacters",
        ],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet helper requests cannot cross the privilege boundary via shell metacharacters or freeform shell strings.",
        sources: &["https://tailscale.com/security-bulletins"],
    },
    ComparativeCatalogEntry {
        project: "OpenVPN",
        incident: "CVE-2024-24974 / CVE-2024-27459 / CVE-2024-27903",
        date: "2024",
        exploit_class: "Privileged local service abuse or escalation",
        summary: "Client or helper surfaces permitted local abuse or privilege escalation.",
        rustynet_analog: "Privileged helper socket trust and strict request validation.",
        attack_family: "helper-input-abuse",
        coverage_status: "covered",
        command_keys: &[
            "control_socket_validator",
            "helper_arg_count",
            "helper_arg_size",
            "helper_no_shell_construction",
        ],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet rejects malformed helper requests and refuses insecure local control surfaces before any privileged action.",
        sources: &["https://openvpn.net/security-advisories/"],
    },
    ComparativeCatalogEntry {
        project: "OpenVPN",
        incident: "CVE-2024-8474",
        date: "2024",
        exploit_class: "Secret leakage in logs",
        summary: "Debug logging exposed private keys or credentials.",
        rustynet_analog: "Structured logging and debug formatting must redact secrets by default.",
        attack_family: "secret-custody",
        coverage_status: "covered",
        command_keys: &["redaction_structured_logs", "redaction_ingestion_paths"],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet logs never emit cleartext secret material.",
        sources: &["https://openvpn.net/security-advisories/"],
    },
    ComparativeCatalogEntry {
        project: "NetBird",
        incident: "2024 Security Announcement",
        date: "2024",
        exploit_class: "Authorization bypass in management API",
        summary: "A valid token could reach resources outside the caller's authorization boundary.",
        rustynet_analog: "Role/auth matrix enforcement and membership-aware policy denial of unauthorized principals.",
        attack_family: "missing-state-fail-closed",
        coverage_status: "covered",
        command_keys: &["role_blocks_admin", "policy_denies_unknown"],
        live_validation_scripts: &[],
        expected_secure_result: "Rustynet denies out-of-role and out-of-membership mutations even when the caller is otherwise authenticated.",
        sources: &["https://forum.netbird.io/t/security-announcement/165"],
    },
    ComparativeCatalogEntry {
        project: "WireGuard-based clients",
        incident: "TunnelCrack",
        date: "2023",
        exploit_class: "Tunnel bypass via local-network and server-IP routing assumptions",
        summary: "VPN clients could leak or bypass traffic because local-network trust and server-route handling were too permissive.",
        rustynet_analog: "Management-bypass and peer-endpoint bypass routes must be tightly scoped and auditable.",
        attack_family: "route-hijack",
        coverage_status: "partially_covered",
        command_keys: &[
            "route_mgmt_bypass_ipv4",
            "route_peer_bypass_ipv4",
            "phase4_fail_closed",
        ],
        live_validation_scripts: &["scripts/e2e/live_linux_server_ip_bypass_test.sh"],
        expected_secure_result: "Rustynet bypass routes are host- or CIDR-scoped and do not create broad tunnel leaks.",
        sources: &["https://tunnelcrack.mathyvanhoef.com/details.html"],
    },
    ComparativeCatalogEntry {
        project: "WireGuard",
        incident: "Known Limitations & Tradeoffs",
        date: "ongoing",
        exploit_class: "Host-integration and endpoint-mobility risk class",
        summary: "WireGuard deliberately leaves policy, identity, and many host-integration responsibilities to the surrounding system.",
        rustynet_analog: "Signed traversal authority and replay-resistant endpoint/state ingestion above the backend.",
        attack_family: "traversal-abuse",
        coverage_status: "partially_covered",
        command_keys: &[
            "traversal_tamper_replay",
            "traversal_wrong_signer",
            "traversal_netcheck_fail_closed",
            "traversal_nat_mismatch",
        ],
        live_validation_scripts: &["scripts/e2e/live_linux_endpoint_hijack_test.sh"],
        expected_secure_result: "Rustynet does not trust raw backend endpoint movement without signed, fresh traversal evidence.",
        sources: &["https://www.wireguard.com/known-limitations/"],
    },
];

pub fn validation_spec_by_mode(mode: &str) -> Option<&'static ValidationSpec> {
    LIVE_VALIDATION_SPECS.iter().find(|spec| spec.mode == mode)
}

pub fn validation_spec_by_key(key: &str) -> Option<&'static ValidationSpec> {
    LIVE_VALIDATION_SPECS.iter().find(|spec| spec.key == key)
}

pub fn sorted_validation_specs() -> Vec<&'static ValidationSpec> {
    let mut specs = LIVE_VALIDATION_SPECS.iter().collect::<Vec<_>>();
    specs.sort_by_key(|spec| spec.key);
    specs
}

pub fn validation_check_metadata(
    spec: &ValidationSpec,
    check_name: &str,
) -> Option<&'static CheckMetadata> {
    spec.check_metadata
        .iter()
        .find(|entry| entry.key == check_name)
        .map(|entry| &entry.metadata)
}

pub fn validation_arg_flag(arg_name: &str) -> Option<&'static str> {
    VALIDATION_ARG_FLAGS
        .iter()
        .find(|(name, _)| *name == arg_name)
        .map(|(_, flag)| *flag)
}

pub fn comparative_command_spec(key: &str) -> Option<&'static ComparativeCommandSpec> {
    COMPARATIVE_COMMAND_SPECS
        .iter()
        .find(|spec| spec.key == key)
}

pub fn comparative_status_order(status: &str) -> usize {
    COMPARATIVE_STATUS_ORDER
        .iter()
        .find(|(candidate, _)| *candidate == status)
        .map(|(_, order)| *order)
        .unwrap_or(usize::MAX)
}
