#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use rustynet_backend_api::{
    BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext, TunnelBackend, TunnelStats,
};
use rustynet_policy::{AccessRequest, Decision, PolicySet, Protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPath {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeGuardConfig {
    pub max_attempts_per_window: u32,
    pub window_secs: u64,
}

impl Default for HandshakeGuardConfig {
    fn default() -> Self {
        Self {
            max_attempts_per_window: 50,
            window_secs: 10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyConfig {
    pub interval_secs: u64,
}

impl Default for RekeyConfig {
    fn default() -> Self {
        Self {
            interval_secs: 15 * 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAccessIntent {
    pub source: String,
    pub destination: String,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSessionSnapshot {
    pub node_id: NodeId,
    pub path: DataPath,
    pub connected_at_unix: u64,
    pub last_rekey_unix: u64,
    pub rekey_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerSessionState {
    path: DataPath,
    connected_at_unix: u64,
    last_rekey_unix: u64,
    rekey_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedMode {
    Disabled,
    TunnelOnly,
    TunnelAndDns,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitNodePolicy {
    allowed_pairs: HashMap<String, Vec<NodeId>>,
}

impl ExitNodePolicy {
    pub fn new() -> Self {
        Self {
            allowed_pairs: HashMap::new(),
        }
    }

    pub fn allow_user_for_node(&mut self, user: &str, node_id: NodeId) {
        self.allowed_pairs
            .entry(user.to_string())
            .or_default()
            .push(node_id);
    }

    pub fn allows(&self, user: &str, node_id: &NodeId) -> bool {
        self.allowed_pairs
            .get(user)
            .map(|entries| entries.iter().any(|candidate| candidate == node_id))
            .unwrap_or(false)
    }
}

impl Default for ExitNodePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsRecord {
    pub hostname: String,
    pub node_id: NodeId,
    pub ip: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MagicDnsZone {
    domain: String,
    records: HashMap<String, MagicDnsRecord>,
    node_index: HashMap<NodeId, String>,
}

impl MagicDnsZone {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_lowercase(),
            records: HashMap::new(),
            node_index: HashMap::new(),
        }
    }

    pub fn upsert(
        &mut self,
        requested_hostname: &str,
        node_id: NodeId,
        ip: &str,
        aliases: Vec<String>,
    ) -> String {
        if let Some(previous_name) = self.node_index.get(&node_id).cloned() {
            self.records.remove(&previous_name);
        }

        let base = normalize_dns_label(requested_hostname);
        let mut candidate = base.clone();
        let mut counter = 2u64;
        while self
            .records
            .get(&candidate)
            .map(|record| record.node_id != node_id)
            .unwrap_or(false)
        {
            candidate = format!("{base}-{counter}");
            counter = counter.saturating_add(1);
        }

        let aliases = aliases
            .into_iter()
            .map(|alias| normalize_dns_label(&alias))
            .collect::<Vec<_>>();
        self.records.insert(
            candidate.clone(),
            MagicDnsRecord {
                hostname: format!("{}.{}", candidate, self.domain),
                node_id: node_id.clone(),
                ip: ip.to_string(),
                aliases,
            },
        );
        self.node_index.insert(node_id, candidate.clone());
        candidate
    }

    pub fn inspect(&self) -> Vec<MagicDnsRecord> {
        let mut entries = self.records.values().cloned().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.hostname.cmp(&right.hostname));
        entries
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataplaneError {
    Backend(BackendError),
    NotStarted,
    PolicyDenied,
    HandshakeRateLimited,
    PeerNotFound,
    ExitNodeNotCapable,
    ExitNodeUnauthorized,
    LanAccessDenied,
    TunnelFailClosed,
    DnsFailClosed,
    InvalidInput,
}

impl std::fmt::Display for DataplaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataplaneError::Backend(err) => write!(f, "backend error: {err}"),
            DataplaneError::NotStarted => f.write_str("dataplane not started"),
            DataplaneError::PolicyDenied => f.write_str("policy denied"),
            DataplaneError::HandshakeRateLimited => f.write_str("handshake rate limited"),
            DataplaneError::PeerNotFound => f.write_str("peer not found"),
            DataplaneError::ExitNodeNotCapable => f.write_str("exit node is not capable"),
            DataplaneError::ExitNodeUnauthorized => {
                f.write_str("exit node is not authorized for user")
            }
            DataplaneError::LanAccessDenied => f.write_str("lan access denied"),
            DataplaneError::TunnelFailClosed => f.write_str("tunnel fail-closed is active"),
            DataplaneError::DnsFailClosed => f.write_str("dns fail-closed is active"),
            DataplaneError::InvalidInput => f.write_str("invalid input"),
        }
    }
}

impl std::error::Error for DataplaneError {}

impl From<BackendError> for DataplaneError {
    fn from(value: BackendError) -> Self {
        DataplaneError::Backend(value)
    }
}

#[derive(Debug, Default)]
pub struct HandshakeFloodGuard {
    config: HandshakeGuardConfig,
    source_attempts: HashMap<String, Vec<u64>>,
}

impl HandshakeFloodGuard {
    pub fn new(config: HandshakeGuardConfig) -> Self {
        Self {
            config,
            source_attempts: HashMap::new(),
        }
    }

    pub fn allow_handshake(&mut self, source: &str, now_unix: u64) -> bool {
        let attempts = self.source_attempts.entry(source.to_string()).or_default();
        let cutoff = now_unix.saturating_sub(self.config.window_secs);
        attempts.retain(|value| *value >= cutoff);
        if attempts.len() as u32 >= self.config.max_attempts_per_window {
            return false;
        }
        attempts.push(now_unix);
        true
    }
}

#[derive(Debug, Default)]
pub struct RekeyManager {
    config: RekeyConfig,
}

impl RekeyManager {
    pub fn new(config: RekeyConfig) -> Self {
        Self { config }
    }

    fn rotate_if_due(&self, session: &mut PeerSessionState, now_unix: u64) -> bool {
        if now_unix.saturating_sub(session.last_rekey_unix) < self.config.interval_secs {
            return false;
        }
        session.last_rekey_unix = now_unix;
        session.rekey_generation = session.rekey_generation.saturating_add(1);
        true
    }
}

pub struct LinuxDataplane<B: TunnelBackend> {
    backend: B,
    local_node: NodeId,
    mesh_cidr: String,
    policy: PolicySet,
    started: bool,
    sessions: HashMap<NodeId, PeerSessionState>,
    handshake_guard: HandshakeFloodGuard,
    rekey_manager: RekeyManager,
    exit_capable_nodes: HashMap<NodeId, bool>,
    selected_exit_node: Option<NodeId>,
    lan_access_enabled: bool,
    lan_route_acl: HashMap<(String, String), bool>,
    advertised_lan_routes: HashMap<NodeId, Vec<String>>,
    protected_mode: ProtectedMode,
    tunnel_up: bool,
    dns_up: bool,
    magic_dns: MagicDnsZone,
}

impl<B: TunnelBackend> LinuxDataplane<B> {
    pub fn new(backend: B, local_node: NodeId, mesh_cidr: String, policy: PolicySet) -> Self {
        Self::with_security(
            backend,
            local_node,
            mesh_cidr,
            policy,
            HandshakeGuardConfig::default(),
            RekeyConfig::default(),
        )
    }

    pub fn with_security(
        backend: B,
        local_node: NodeId,
        mesh_cidr: String,
        policy: PolicySet,
        handshake_guard_config: HandshakeGuardConfig,
        rekey_config: RekeyConfig,
    ) -> Self {
        Self {
            backend,
            local_node,
            mesh_cidr,
            policy,
            started: false,
            sessions: HashMap::new(),
            handshake_guard: HandshakeFloodGuard::new(handshake_guard_config),
            rekey_manager: RekeyManager::new(rekey_config),
            exit_capable_nodes: HashMap::new(),
            selected_exit_node: None,
            lan_access_enabled: false,
            lan_route_acl: HashMap::new(),
            advertised_lan_routes: HashMap::new(),
            protected_mode: ProtectedMode::Disabled,
            tunnel_up: true,
            dns_up: true,
            magic_dns: MagicDnsZone::new("rustynet"),
        }
    }

    pub fn start(&mut self) -> Result<(), DataplaneError> {
        self.backend.start(RuntimeContext {
            local_node: self.local_node.clone(),
            mesh_cidr: self.mesh_cidr.clone(),
        })?;
        self.started = true;
        Ok(())
    }

    pub fn connect_peer(
        &mut self,
        peer: PeerConfig,
        access_intent: &PeerAccessIntent,
        handshake_source_ip: &str,
        now_unix: u64,
    ) -> Result<(), DataplaneError> {
        self.ensure_started()?;
        if !self
            .handshake_guard
            .allow_handshake(handshake_source_ip, now_unix)
        {
            return Err(DataplaneError::HandshakeRateLimited);
        }

        let request = AccessRequest {
            src: access_intent.source.clone(),
            dst: access_intent.destination.clone(),
            protocol: access_intent.protocol,
        };
        if self.policy.evaluate(&request) != Decision::Allow {
            return Err(DataplaneError::PolicyDenied);
        }

        let node_id = peer.node_id.clone();
        self.backend.configure_peer(peer)?;
        self.sessions.insert(
            node_id,
            PeerSessionState {
                path: DataPath::Direct,
                connected_at_unix: now_unix,
                last_rekey_unix: now_unix,
                rekey_generation: 0,
            },
        );
        Ok(())
    }

    pub fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), DataplaneError> {
        self.ensure_started()?;
        if !self.sessions.contains_key(node_id) {
            return Err(DataplaneError::PeerNotFound);
        }

        self.backend.remove_peer(node_id)?;
        self.sessions.remove(node_id);
        Ok(())
    }

    pub fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), DataplaneError> {
        self.ensure_started()?;
        self.backend.apply_routes(routes)?;
        Ok(())
    }

    pub fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), DataplaneError> {
        self.ensure_started()?;
        self.backend.set_exit_mode(mode)?;
        Ok(())
    }

    pub fn set_exit_capable(&mut self, node_id: NodeId, enabled: bool) {
        self.exit_capable_nodes.insert(node_id, enabled);
    }

    pub fn select_exit_node(
        &mut self,
        user: &str,
        node_id: NodeId,
        policy: &ExitNodePolicy,
    ) -> Result<(), DataplaneError> {
        self.ensure_started()?;
        if !self
            .exit_capable_nodes
            .get(&node_id)
            .copied()
            .unwrap_or(false)
        {
            return Err(DataplaneError::ExitNodeNotCapable);
        }
        if !policy.allows(user, &node_id) {
            return Err(DataplaneError::ExitNodeUnauthorized);
        }

        self.selected_exit_node = Some(node_id);
        self.set_exit_mode(ExitMode::FullTunnel)
    }

    pub fn clear_exit_node(&mut self) -> Result<(), DataplaneError> {
        self.ensure_started()?;
        self.selected_exit_node = None;
        self.set_exit_mode(ExitMode::Off)
    }

    pub fn selected_exit_node(&self) -> Option<NodeId> {
        self.selected_exit_node.clone()
    }

    pub fn set_lan_access(&mut self, enabled: bool) {
        self.lan_access_enabled = enabled;
    }

    pub fn advertise_lan_route(&mut self, node_id: NodeId, cidr: &str) {
        self.advertised_lan_routes
            .entry(node_id)
            .or_default()
            .push(cidr.to_string());
    }

    pub fn set_lan_route_permission(&mut self, user: &str, cidr: &str, allowed: bool) {
        self.lan_route_acl
            .insert((user.to_string(), cidr.to_string()), allowed);
    }

    pub fn ensure_lan_route_allowed(&self, user: &str, cidr: &str) -> Result<(), DataplaneError> {
        if !self.lan_access_enabled {
            return Err(DataplaneError::LanAccessDenied);
        }

        let Some(selected_exit) = &self.selected_exit_node else {
            return Err(DataplaneError::LanAccessDenied);
        };

        let route_is_advertised = self
            .advertised_lan_routes
            .get(selected_exit)
            .map(|routes| routes.iter().any(|route| route == cidr))
            .unwrap_or(false);
        if !route_is_advertised {
            return Err(DataplaneError::LanAccessDenied);
        }

        let allowed = self
            .lan_route_acl
            .get(&(user.to_string(), cidr.to_string()))
            .copied()
            .unwrap_or(false);
        if !allowed {
            return Err(DataplaneError::LanAccessDenied);
        }

        Ok(())
    }

    pub fn set_protected_mode(&mut self, mode: ProtectedMode) {
        self.protected_mode = mode;
    }

    pub fn set_tunnel_health(&mut self, healthy: bool) {
        self.tunnel_up = healthy;
    }

    pub fn set_dns_health(&mut self, healthy: bool) {
        self.dns_up = healthy;
    }

    pub fn ensure_egress_allowed(&self) -> Result<(), DataplaneError> {
        if matches!(
            self.protected_mode,
            ProtectedMode::TunnelOnly | ProtectedMode::TunnelAndDns
        ) && !self.tunnel_up
        {
            return Err(DataplaneError::TunnelFailClosed);
        }
        Ok(())
    }

    pub fn ensure_dns_allowed(&self) -> Result<(), DataplaneError> {
        if self.protected_mode == ProtectedMode::TunnelAndDns {
            if !self.tunnel_up {
                return Err(DataplaneError::TunnelFailClosed);
            }
            if !self.dns_up {
                return Err(DataplaneError::DnsFailClosed);
            }
        }
        Ok(())
    }

    pub fn upsert_magic_dns_record(
        &mut self,
        requested_hostname: &str,
        node_id: NodeId,
        ip: &str,
        aliases: Vec<String>,
    ) -> String {
        self.magic_dns
            .upsert(requested_hostname, node_id, ip, aliases)
    }

    pub fn inspect_magic_dns(&self) -> Vec<MagicDnsRecord> {
        self.magic_dns.inspect()
    }

    pub fn mark_direct_path_failed(&mut self, node_id: &NodeId) -> Result<(), DataplaneError> {
        self.ensure_started()?;
        let Some(session) = self.sessions.get_mut(node_id) else {
            return Err(DataplaneError::PeerNotFound);
        };
        session.path = DataPath::Relay;
        Ok(())
    }

    pub fn mark_direct_path_recovered(&mut self, node_id: &NodeId) -> Result<(), DataplaneError> {
        self.ensure_started()?;
        let Some(session) = self.sessions.get_mut(node_id) else {
            return Err(DataplaneError::PeerNotFound);
        };
        session.path = DataPath::Direct;
        Ok(())
    }

    pub fn rotate_due_keys(&mut self, now_unix: u64) -> Result<usize, DataplaneError> {
        self.ensure_started()?;
        let mut count = 0usize;
        for session in self.sessions.values_mut() {
            if self.rekey_manager.rotate_if_due(session, now_unix) {
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn session_snapshot(&self, node_id: &NodeId) -> Option<PeerSessionSnapshot> {
        self.sessions.get(node_id).map(|state| PeerSessionSnapshot {
            node_id: node_id.clone(),
            path: state.path,
            connected_at_unix: state.connected_at_unix,
            last_rekey_unix: state.last_rekey_unix,
            rekey_generation: state.rekey_generation,
        })
    }

    pub fn has_relay_path(&self) -> bool {
        self.sessions
            .values()
            .any(|session| session.path == DataPath::Relay)
    }

    pub fn backend_stats(&self) -> Result<TunnelStats, DataplaneError> {
        self.ensure_started()?;
        self.backend.stats().map_err(DataplaneError::Backend)
    }

    pub fn shutdown(&mut self) -> Result<(), DataplaneError> {
        self.ensure_started()?;
        self.backend.shutdown()?;
        self.sessions.clear();
        self.selected_exit_node = None;
        self.lan_access_enabled = false;
        self.started = false;
        Ok(())
    }

    fn ensure_started(&self) -> Result<(), DataplaneError> {
        if self.started {
            return Ok(());
        }
        Err(DataplaneError::NotStarted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Phase3MeshMetric {
    pub name: &'static str,
    pub value: f64,
    pub unit: &'static str,
}

pub fn write_phase3_mesh_report(
    path: impl AsRef<Path>,
    connected_nodes: usize,
    total_peer_sessions: usize,
    relay_session_count: usize,
) -> Result<(), String> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create_dir_all failed: {err}"))?;
    }

    let metrics = [
        Phase3MeshMetric {
            name: "connected_nodes",
            value: connected_nodes as f64,
            unit: "count",
        },
        Phase3MeshMetric {
            name: "peer_sessions",
            value: total_peer_sessions as f64,
            unit: "count",
        },
        Phase3MeshMetric {
            name: "relay_sessions",
            value: relay_session_count as f64,
            unit: "count",
        },
    ];

    let mut encoded = String::from("{\n  \"phase\":\"phase3\",\n  \"metrics\":[\n");
    for (index, metric) in metrics.iter().enumerate() {
        let comma = if index + 1 == metrics.len() { "" } else { "," };
        encoded.push_str(&format!(
            "    {{\"name\":\"{}\",\"value\":{},\"unit\":\"{}\"}}{}\n",
            metric.name, metric.value, metric.unit, comma
        ));
    }
    encoded.push_str("  ]\n}\n");

    fs::write(path, encoded).map_err(|err| format!("write phase3 report failed: {err}"))?;
    Ok(())
}

fn normalize_dns_label(value: &str) -> String {
    let mut out = String::new();
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            out.push(ch.to_ascii_lowercase());
        } else if ch == ' ' || ch == '_' {
            out.push('-');
        }
    }
    if out.is_empty() {
        "node".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use rustynet_backend_api::{NodeId, PeerConfig, Route, RouteKind, SocketEndpoint};
    use rustynet_backend_wireguard::WireguardBackend;
    use rustynet_policy::{PolicyRule, RuleAction};

    use super::{
        DataPath, DataplaneError, ExitNodePolicy, HandshakeGuardConfig, LinuxDataplane,
        PeerAccessIntent, ProtectedMode, RekeyConfig, write_phase3_mesh_report,
    };

    fn allow_all_policy() -> rustynet_policy::PolicySet {
        rustynet_policy::PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_string(),
                dst: "*".to_string(),
                protocol: rustynet_policy::Protocol::Any,
                action: RuleAction::Allow,
            }],
        }
    }

    fn default_intent() -> PeerAccessIntent {
        PeerAccessIntent {
            source: "group:family".to_string(),
            destination: "tag:servers".to_string(),
            protocol: rustynet_policy::Protocol::Tcp,
        }
    }

    fn peer_config(id: &str, ip: &str) -> PeerConfig {
        PeerConfig {
            node_id: NodeId::new(id).expect("node id should be valid"),
            endpoint: SocketEndpoint {
                addr: ip.parse::<IpAddr>().expect("endpoint ip should parse"),
                port: 51820,
            },
            public_key: [7; 32],
            allowed_ips: vec!["100.100.10.1/32".to_string()],
        }
    }

    #[test]
    fn phase3_linux_dataplane_lifecycle_and_route_flow() {
        let local_node = NodeId::new("node-a").expect("local id should be valid");
        let mut dataplane = LinuxDataplane::new(
            WireguardBackend::default(),
            local_node,
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
        );

        dataplane.start().expect("dataplane should start");
        dataplane
            .connect_peer(
                peer_config("node-b", "203.0.113.10"),
                &default_intent(),
                "198.51.100.10",
                1_000,
            )
            .expect("peer should connect");
        dataplane
            .apply_routes(vec![Route {
                destination_cidr: "100.100.20.0/24".to_string(),
                via_node: NodeId::new("node-b").expect("id should parse"),
                kind: RouteKind::Mesh,
            }])
            .expect("routes should apply");
        dataplane
            .set_exit_mode(rustynet_backend_api::ExitMode::Off)
            .expect("exit mode should apply");

        let stats = dataplane
            .backend_stats()
            .expect("stats should be available");
        assert_eq!(stats.peer_count, 1);
        dataplane.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn phase3_default_deny_blocks_peer_connection() {
        let local_node = NodeId::new("node-a").expect("local id should be valid");
        let mut dataplane = LinuxDataplane::new(
            WireguardBackend::default(),
            local_node,
            "100.64.0.0/10".to_string(),
            rustynet_policy::PolicySet::default(),
        );

        dataplane.start().expect("dataplane should start");
        let denied = dataplane.connect_peer(
            peer_config("node-b", "203.0.113.10"),
            &default_intent(),
            "198.51.100.10",
            1_000,
        );
        assert_eq!(denied.err(), Some(DataplaneError::PolicyDenied));
    }

    #[test]
    fn phase3_direct_path_prefers_direct_then_falls_back_to_relay() {
        let local_node = NodeId::new("node-a").expect("local id should be valid");
        let mut dataplane = LinuxDataplane::new(
            WireguardBackend::default(),
            local_node,
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
        );
        let peer_id = NodeId::new("node-b").expect("peer id should be valid");

        dataplane.start().expect("dataplane should start");
        dataplane
            .connect_peer(
                peer_config("node-b", "203.0.113.10"),
                &default_intent(),
                "198.51.100.10",
                1_000,
            )
            .expect("peer should connect");
        assert_eq!(
            dataplane
                .session_snapshot(&peer_id)
                .expect("session should exist")
                .path,
            DataPath::Direct
        );

        dataplane
            .mark_direct_path_failed(&peer_id)
            .expect("direct path failure should be accepted");
        assert!(dataplane.has_relay_path());
        assert_eq!(
            dataplane
                .session_snapshot(&peer_id)
                .expect("session should exist")
                .path,
            DataPath::Relay
        );

        dataplane
            .mark_direct_path_recovered(&peer_id)
            .expect("direct path recovery should be accepted");
        assert_eq!(
            dataplane
                .session_snapshot(&peer_id)
                .expect("session should exist")
                .path,
            DataPath::Direct
        );
    }

    #[test]
    fn phase3_handshake_guard_limits_burst() {
        let local_node = NodeId::new("node-a").expect("local id should be valid");
        let mut dataplane = LinuxDataplane::with_security(
            WireguardBackend::default(),
            local_node,
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
            HandshakeGuardConfig {
                max_attempts_per_window: 1,
                window_secs: 30,
            },
            RekeyConfig::default(),
        );

        dataplane.start().expect("dataplane should start");
        dataplane
            .connect_peer(
                peer_config("node-b", "203.0.113.10"),
                &default_intent(),
                "198.51.100.10",
                1_000,
            )
            .expect("first handshake should pass");

        let second = dataplane.connect_peer(
            peer_config("node-c", "203.0.113.11"),
            &default_intent(),
            "198.51.100.10",
            1_001,
        );
        assert_eq!(second.err(), Some(DataplaneError::HandshakeRateLimited));
    }

    #[test]
    fn phase3_rekey_rotation_advances_generation() {
        let local_node = NodeId::new("node-a").expect("local id should be valid");
        let mut dataplane = LinuxDataplane::with_security(
            WireguardBackend::default(),
            local_node,
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
            HandshakeGuardConfig::default(),
            RekeyConfig { interval_secs: 60 },
        );
        let peer_id = NodeId::new("node-b").expect("peer id should be valid");

        dataplane.start().expect("dataplane should start");
        dataplane
            .connect_peer(
                peer_config("node-b", "203.0.113.10"),
                &default_intent(),
                "198.51.100.10",
                1_000,
            )
            .expect("peer should connect");
        let rotated = dataplane
            .rotate_due_keys(1_070)
            .expect("rotation should run");
        assert_eq!(rotated, 1);
        assert_eq!(
            dataplane
                .session_snapshot(&peer_id)
                .expect("session should exist")
                .rekey_generation,
            1
        );
    }

    #[test]
    fn phase3_three_node_mesh_succeeds() {
        let mut node_a = LinuxDataplane::new(
            WireguardBackend::default(),
            NodeId::new("node-a").expect("node id should be valid"),
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
        );
        let mut node_b = LinuxDataplane::new(
            WireguardBackend::default(),
            NodeId::new("node-b").expect("node id should be valid"),
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
        );
        let mut node_c = LinuxDataplane::new(
            WireguardBackend::default(),
            NodeId::new("node-c").expect("node id should be valid"),
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
        );

        node_a.start().expect("node a should start");
        node_b.start().expect("node b should start");
        node_c.start().expect("node c should start");

        node_a
            .connect_peer(
                peer_config("node-b", "203.0.113.10"),
                &default_intent(),
                "198.51.100.10",
                1_000,
            )
            .expect("a->b should connect");
        node_a
            .connect_peer(
                peer_config("node-c", "203.0.113.11"),
                &default_intent(),
                "198.51.100.10",
                1_001,
            )
            .expect("a->c should connect");

        node_b
            .connect_peer(
                peer_config("node-a", "203.0.113.12"),
                &default_intent(),
                "198.51.100.20",
                1_002,
            )
            .expect("b->a should connect");
        node_b
            .connect_peer(
                peer_config("node-c", "203.0.113.11"),
                &default_intent(),
                "198.51.100.20",
                1_003,
            )
            .expect("b->c should connect");

        node_c
            .connect_peer(
                peer_config("node-a", "203.0.113.12"),
                &default_intent(),
                "198.51.100.30",
                1_004,
            )
            .expect("c->a should connect");
        node_c
            .connect_peer(
                peer_config("node-b", "203.0.113.10"),
                &default_intent(),
                "198.51.100.30",
                1_005,
            )
            .expect("c->b should connect");

        assert_eq!(
            node_a
                .backend_stats()
                .expect("a stats should work")
                .peer_count,
            2
        );
        assert_eq!(
            node_b
                .backend_stats()
                .expect("b stats should work")
                .peer_count,
            2
        );
        assert_eq!(
            node_c
                .backend_stats()
                .expect("c stats should work")
                .peer_count,
            2
        );

        let report_path = std::env::var("RUSTYNET_PHASE3_MESH_REPORT")
            .unwrap_or_else(|_| "artifacts/perf/phase3/mesh_baseline.json".to_string());
        write_phase3_mesh_report(&report_path, 3, 6, 0).expect("phase3 report should be written");
    }

    #[test]
    fn phase4_exit_node_selection_and_lan_toggle_are_enforced() {
        let mut dataplane = LinuxDataplane::new(
            WireguardBackend::default(),
            NodeId::new("node-a").expect("node id should be valid"),
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
        );
        let exit_node = NodeId::new("node-exit").expect("node id should be valid");

        dataplane.start().expect("dataplane should start");
        dataplane.set_exit_capable(exit_node.clone(), true);

        let mut policy = ExitNodePolicy::new();
        policy.allow_user_for_node("alice@example.local", exit_node.clone());

        dataplane
            .select_exit_node("alice@example.local", exit_node.clone(), &policy)
            .expect("authorized exit selection should succeed");
        assert_eq!(dataplane.selected_exit_node(), Some(exit_node.clone()));

        dataplane.advertise_lan_route(exit_node, "192.168.1.0/24");
        dataplane.set_lan_route_permission("alice@example.local", "192.168.1.0/24", true);

        let blocked = dataplane.ensure_lan_route_allowed("alice@example.local", "192.168.1.0/24");
        assert_eq!(blocked.err(), Some(DataplaneError::LanAccessDenied));

        dataplane.set_lan_access(true);
        dataplane
            .ensure_lan_route_allowed("alice@example.local", "192.168.1.0/24")
            .expect("lan access should be allowed when toggle and acl are enabled");

        dataplane.set_lan_access(false);
        let denied_again =
            dataplane.ensure_lan_route_allowed("alice@example.local", "192.168.1.0/24");
        assert_eq!(denied_again.err(), Some(DataplaneError::LanAccessDenied));
    }

    #[test]
    fn phase4_magic_dns_handles_duplicate_hostnames_deterministically() {
        let mut dataplane = LinuxDataplane::new(
            WireguardBackend::default(),
            NodeId::new("node-a").expect("node id should be valid"),
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
        );
        dataplane.start().expect("dataplane should start");

        let primary_name = dataplane.upsert_magic_dns_record(
            "NAS",
            NodeId::new("node-nas-1").expect("node id should be valid"),
            "100.100.10.10",
            vec!["storage".to_string()],
        );
        let duplicate_name = dataplane.upsert_magic_dns_record(
            "nas",
            NodeId::new("node-nas-2").expect("node id should be valid"),
            "100.100.10.11",
            vec!["backup".to_string()],
        );

        assert_eq!(primary_name, "nas");
        assert_eq!(duplicate_name, "nas-2");

        let records = dataplane.inspect_magic_dns();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].hostname, "nas-2.rustynet");
        assert_eq!(records[1].hostname, "nas.rustynet");
    }

    #[test]
    fn phase4_fail_close_blocks_tunnel_and_dns_when_required() {
        let mut dataplane = LinuxDataplane::new(
            WireguardBackend::default(),
            NodeId::new("node-a").expect("node id should be valid"),
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
        );
        dataplane.start().expect("dataplane should start");

        dataplane.set_protected_mode(ProtectedMode::TunnelAndDns);
        dataplane.set_tunnel_health(false);
        let egress = dataplane.ensure_egress_allowed();
        assert_eq!(egress.err(), Some(DataplaneError::TunnelFailClosed));
        let dns = dataplane.ensure_dns_allowed();
        assert_eq!(dns.err(), Some(DataplaneError::TunnelFailClosed));

        dataplane.set_tunnel_health(true);
        dataplane.set_dns_health(false);
        let dns = dataplane.ensure_dns_allowed();
        assert_eq!(dns.err(), Some(DataplaneError::DnsFailClosed));

        dataplane.set_protected_mode(ProtectedMode::Disabled);
        dataplane
            .ensure_egress_allowed()
            .expect("egress should be permitted when protected mode is disabled");
        dataplane
            .ensure_dns_allowed()
            .expect("dns should be permitted when protected mode is disabled");
    }

    #[test]
    fn phase4_exit_node_clear_removes_selection() {
        let mut dataplane = LinuxDataplane::new(
            WireguardBackend::default(),
            NodeId::new("node-a").expect("node id should be valid"),
            "100.64.0.0/10".to_string(),
            allow_all_policy(),
        );
        let exit_node = NodeId::new("node-exit").expect("node id should be valid");
        let mut policy = ExitNodePolicy::new();
        policy.allow_user_for_node("alice@example.local", exit_node.clone());

        dataplane.start().expect("dataplane should start");
        dataplane.set_exit_capable(exit_node.clone(), true);
        dataplane
            .select_exit_node("alice@example.local", exit_node, &policy)
            .expect("selection should succeed");

        dataplane
            .clear_exit_node()
            .expect("clearing exit node should succeed");
        assert_eq!(dataplane.selected_exit_node(), None);
    }
}
