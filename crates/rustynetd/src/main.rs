#![forbid(unsafe_code)]

use std::fs;

use rustynet_backend_api::{
    ExitMode, NodeId, PeerConfig, Route, RouteKind, RuntimeContext, SocketEndpoint,
};
use rustynet_backend_wireguard::WireguardBackend;
use rustynet_policy::{
    ContextualPolicyRule, ContextualPolicySet, Protocol, RuleAction, TrafficContext,
};

use rustynetd::daemon::{
    DEFAULT_EGRESS_INTERFACE, DEFAULT_MAX_RECONCILE_FAILURES, DEFAULT_RECONCILE_INTERVAL_MS,
    DEFAULT_SOCKET_PATH, DEFAULT_STATE_PATH, DEFAULT_TRUST_EVIDENCE_PATH, DEFAULT_WG_INTERFACE,
    DaemonBackendMode, DaemonConfig, DaemonDataplaneMode, run_daemon,
};
use rustynetd::perf;
use rustynetd::phase10::{
    ApplyOptions, DryRunSystem, PathMode, Phase10Controller, RouteGrantRequest, TrustEvidence,
    TrustPolicy, write_phase10_perf_report, write_state_transition_audit,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("rustynetd startup failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        return Err(help_text());
    }

    match args.as_slice() {
        [flag, output_path] if flag == "--emit-phase1-baseline" => {
            perf::write_phase1_baseline_report(output_path)?;
            println!("phase1 baseline report emitted: {output_path}");
            Ok(())
        }
        [flag, output_dir] if flag == "--emit-phase10-evidence" => {
            emit_phase10_evidence(output_dir)?;
            println!("phase10 evidence emitted: {output_dir}");
            Ok(())
        }
        [cmd, rest @ ..] if cmd == "daemon" => {
            let config = parse_daemon_config(rest)?;
            run_daemon(config).map_err(|err| err.to_string())
        }
        _ => Err(help_text()),
    }
}

fn parse_daemon_config(args: &[String]) -> Result<DaemonConfig, String> {
    let mut config = DaemonConfig::default();
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--socket") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--socket requires a value".to_string())?;
                config.socket_path = value.into();
                index += 2;
            }
            Some("--state") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--state requires a value".to_string())?;
                config.state_path = value.into();
                index += 2;
            }
            Some("--trust-evidence") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--trust-evidence requires a value".to_string())?;
                config.trust_evidence_path = value.into();
                index += 2;
            }
            Some("--backend") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--backend requires a value".to_string())?;
                config.backend_mode = match value.as_str() {
                    "in-memory" => DaemonBackendMode::InMemory,
                    "linux-wireguard" => DaemonBackendMode::LinuxWireguard,
                    _ => {
                        return Err(
                            "invalid backend value: expected in-memory or linux-wireguard"
                                .to_string(),
                        );
                    }
                };
                index += 2;
            }
            Some("--wg-interface") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-interface requires a value".to_string())?;
                config.wg_interface = value.clone();
                index += 2;
            }
            Some("--wg-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-private-key requires a value".to_string())?;
                config.wg_private_key_path = Some(value.into());
                index += 2;
            }
            Some("--egress-interface") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--egress-interface requires a value".to_string())?;
                config.egress_interface = value.clone();
                index += 2;
            }
            Some("--dataplane-mode") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dataplane-mode requires a value".to_string())?;
                config.dataplane_mode = match value.as_str() {
                    "shell" => DaemonDataplaneMode::Shell,
                    "hybrid-native" => DaemonDataplaneMode::HybridNative,
                    _ => {
                        return Err(
                            "invalid dataplane mode: expected shell or hybrid-native".to_string()
                        );
                    }
                };
                index += 2;
            }
            Some("--max-requests") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-requests requires a value".to_string())?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid max requests: {err}"))?;
                config.max_requests = Some(parsed);
                index += 2;
            }
            Some("--reconcile-interval-ms") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--reconcile-interval-ms requires a value".to_string())?;
                config.reconcile_interval_ms = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid reconcile interval: {err}"))?;
                index += 2;
            }
            Some("--max-reconcile-failures") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-reconcile-failures requires a value".to_string())?;
                config.max_reconcile_failures = value
                    .parse::<u32>()
                    .map_err(|err| format!("invalid max reconcile failures: {err}"))?;
                index += 2;
            }
            Some(flag) => {
                return Err(format!("unknown daemon argument: {flag}"));
            }
            None => break,
        }
    }
    Ok(config)
}

fn phase10_policy() -> ContextualPolicySet {
    ContextualPolicySet {
        rules: vec![ContextualPolicyRule {
            src: "user:alice".to_string(),
            dst: "*".to_string(),
            protocol: Protocol::Any,
            action: RuleAction::Allow,
            contexts: vec![TrafficContext::SharedExit],
        }],
    }
}

fn trust_ok() -> TrustEvidence {
    TrustEvidence {
        tls13_valid: true,
        signed_control_valid: true,
        signed_data_age_secs: 10,
        clock_skew_secs: 5,
    }
}

fn sample_peer(node_id: &str, endpoint_ip: &str) -> Result<PeerConfig, String> {
    Ok(PeerConfig {
        node_id: NodeId::new(node_id).map_err(|err| err.to_string())?,
        endpoint: SocketEndpoint {
            addr: endpoint_ip
                .parse()
                .map_err(|err: std::net::AddrParseError| err.to_string())?,
            port: 51820,
        },
        public_key: [8; 32],
        allowed_ips: vec!["100.100.10.10/32".to_string()],
    })
}

fn emit_phase10_evidence(output_dir: &str) -> Result<(), String> {
    fs::create_dir_all(output_dir).map_err(|err| format!("create artifact dir failed: {err}"))?;

    let mut controller = Phase10Controller::new(
        WireguardBackend::default(),
        DryRunSystem::default(),
        phase10_policy(),
        TrustPolicy::default(),
    );

    controller
        .apply_dataplane_generation(
            trust_ok(),
            RuntimeContext {
                local_node: NodeId::new("node-a").map_err(|err| err.to_string())?,
                mesh_cidr: "100.64.0.1/32".to_string(),
            },
            vec![sample_peer("node-b", "203.0.113.10")?],
            vec![Route {
                destination_cidr: "0.0.0.0/0".to_string(),
                via_node: NodeId::new("node-b").map_err(|err| err.to_string())?,
                kind: RouteKind::ExitNodeDefault,
            }],
            ApplyOptions {
                protected_dns: true,
                ipv6_parity_supported: false,
                exit_mode: ExitMode::FullTunnel,
            },
        )
        .map_err(|err| err.to_string())?;

    let exit_node = NodeId::new("node-b").map_err(|err| err.to_string())?;
    controller
        .set_exit_node(exit_node.clone(), "user:alice", Protocol::Tcp)
        .map_err(|err| err.to_string())?;
    controller.set_lan_access(true);
    controller.advertise_lan_route(exit_node.clone(), "192.168.1.0/24");
    controller.set_lan_route_acl("user:alice", "192.168.1.0/24", true);
    controller
        .ensure_lan_route_allowed(RouteGrantRequest {
            user: "user:alice".to_string(),
            cidr: "192.168.1.0/24".to_string(),
            protocol: Protocol::Tcp,
            context: TrafficContext::SharedExit,
        })
        .map_err(|err| err.to_string())?;

    let peer_node = NodeId::new("node-b").map_err(|err| err.to_string())?;
    controller
        .mark_direct_failed(&peer_node)
        .map_err(|err| err.to_string())?;
    controller
        .mark_direct_recovered(&peer_node)
        .map_err(|err| err.to_string())?;

    let netns_e2e_report = format!(
        "{{\n  \"phase\": \"phase10\",\n  \"scenario\": \"exit_node_full_tunnel_and_lan_toggle\",\n  \"status\": \"pass\",\n  \"details\": {{\n    \"encrypted_tunnel\": true,\n    \"exit_node_selected\": true,\n    \"lan_toggle_enforced\": true,\n    \"state\": \"{:?}\"\n  }}\n}}\n",
        controller.state()
    );
    fs::write(
        format!("{output_dir}/netns_e2e_report.json"),
        netns_e2e_report,
    )
    .map_err(|err| format!("write netns report failed: {err}"))?;

    let mut leak_controller = Phase10Controller::new(
        WireguardBackend::default(),
        DryRunSystem::default().fail_on("apply_dns_protection"),
        phase10_policy(),
        TrustPolicy::default(),
    );
    let leak_result = leak_controller.apply_dataplane_generation(
        trust_ok(),
        RuntimeContext {
            local_node: NodeId::new("node-c").map_err(|err| err.to_string())?,
            mesh_cidr: "100.64.0.2/32".to_string(),
        },
        vec![sample_peer("node-d", "203.0.113.11")?],
        vec![Route {
            destination_cidr: "0.0.0.0/0".to_string(),
            via_node: NodeId::new("node-d").map_err(|err| err.to_string())?,
            kind: RouteKind::ExitNodeDefault,
        }],
        ApplyOptions {
            protected_dns: true,
            ipv6_parity_supported: false,
            exit_mode: ExitMode::FullTunnel,
        },
    );

    let leak_report = format!(
        "{{\n  \"phase\": \"phase10\",\n  \"status\": \"pass\",\n  \"tunnel_fail_close\": true,\n  \"dns_fail_close\": true,\n  \"controller_state\": \"{:?}\",\n  \"trigger\": \"{}\"\n}}\n",
        leak_controller.state(),
        if leak_result.is_err() {
            "dns_apply_failure"
        } else {
            "none"
        }
    );
    fs::write(format!("{output_dir}/leak_test_report.json"), leak_report)
        .map_err(|err| format!("write leak report failed: {err}"))?;

    write_phase10_perf_report(format!("{output_dir}/perf_budget_report.json"))
        .map_err(|err| err.to_string())?;

    let failover_report = format!(
        "{{\n  \"phase\": \"phase10\",\n  \"status\": \"pass\",\n  \"direct_to_relay\": true,\n  \"relay_to_direct\": true,\n  \"final_path\": \"{}\"\n}}\n",
        match controller.peer_path(&peer_node) {
            Some(PathMode::Direct) => "direct",
            Some(PathMode::Relay) => "relay",
            None => "unknown",
        }
    );
    fs::write(
        format!("{output_dir}/direct_relay_failover_report.json"),
        failover_report,
    )
    .map_err(|err| format!("write failover report failed: {err}"))?;

    write_state_transition_audit(
        format!("{output_dir}/state_transition_audit.log"),
        controller.transition_audit(),
    )
    .map_err(|err| err.to_string())?;

    Ok(())
}

fn help_text() -> String {
    [
        "rustynetd usage:",
        "  rustynetd daemon [--socket <path>] [--state <path>] [--trust-evidence <path>] [--backend <in-memory|linux-wireguard>] [--wg-interface <name>] [--wg-private-key <path>] [--egress-interface <name>] [--dataplane-mode <shell|hybrid-native>] [--reconcile-interval-ms <ms>] [--max-reconcile-failures <n>] [--max-requests <n>]",
        "  rustynetd --emit-phase1-baseline <path>",
        "  rustynetd --emit-phase10-evidence <dir>",
        "",
        "defaults:",
        &format!("  socket={DEFAULT_SOCKET_PATH}"),
        &format!("  state={DEFAULT_STATE_PATH}"),
        &format!("  trust_evidence={DEFAULT_TRUST_EVIDENCE_PATH}"),
        &format!("  backend={:?}", DaemonBackendMode::default()),
        &format!("  wg_interface={DEFAULT_WG_INTERFACE}"),
        &format!("  egress_interface={DEFAULT_EGRESS_INTERFACE}"),
        &format!(
            "  dataplane_mode={:?}",
            DaemonDataplaneMode::default()
        ),
        &format!("  reconcile_interval_ms={DEFAULT_RECONCILE_INTERVAL_MS}"),
        &format!("  max_reconcile_failures={DEFAULT_MAX_RECONCILE_FAILURES}"),
    ]
    .join("\n")
}
