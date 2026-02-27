#![forbid(unsafe_code)]

use rustynet_backend_api::{
    ExitMode, NodeId, PeerConfig, Route, RouteKind, RuntimeContext, SocketEndpoint, TunnelBackend,
};
use rustynet_backend_wireguard::WireguardBackend;
use rustynet_crypto::NodeKeyPair;
use rustynet_policy::{AccessRequest, PolicyRule, PolicySet, Protocol, RuleAction};

fn main() {
    if let Err(err) = run() {
        eprintln!("rustynetd startup failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let local_node = NodeId::new("mini-pc-1").map_err(|err| err.to_string())?;
    let peer_node = NodeId::new("laptop-1").map_err(|err| err.to_string())?;

    let mut backend = WireguardBackend::default();
    backend
        .start(RuntimeContext {
            local_node: local_node.clone(),
            mesh_cidr: "100.64.0.0/10".to_string(),
        })
        .map_err(|err| err.to_string())?;

    backend
        .configure_peer(PeerConfig {
            node_id: peer_node.clone(),
            endpoint: SocketEndpoint {
                addr: "203.0.113.10"
                    .parse()
                    .map_err(|err: std::net::AddrParseError| err.to_string())?,
                port: 51820,
            },
            public_key: [8; 32],
            allowed_ips: vec!["100.100.1.10/32".to_string()],
        })
        .map_err(|err| err.to_string())?;

    backend
        .apply_routes(vec![Route {
            destination_cidr: "0.0.0.0/0".to_string(),
            via_node: peer_node,
            kind: RouteKind::ExitNodeDefault,
        }])
        .map_err(|err| err.to_string())?;

    backend
        .set_exit_mode(ExitMode::FullTunnel)
        .map_err(|err| err.to_string())?;

    let policy = PolicySet {
        rules: vec![PolicyRule {
            src: "group:family".to_string(),
            dst: "tag:servers".to_string(),
            protocol: Protocol::Tcp,
            action: RuleAction::Allow,
        }],
    };

    let policy_decision = policy.evaluate(&AccessRequest {
        src: "group:family".to_string(),
        dst: "tag:servers".to_string(),
        protocol: Protocol::Tcp,
    });

    let keypair = NodeKeyPair::from_raw([3; 32], [4; 32]).map_err(|err| err.to_string())?;

    let stats = backend.stats().map_err(|err| err.to_string())?;
    println!(
        "rustynetd scaffold online: backend={} peers={} decision={policy_decision:?} pubkey_prefix={}",
        backend.name(),
        stats.peer_count,
        keypair.public_key.as_bytes()[0]
    );

    Ok(())
}
