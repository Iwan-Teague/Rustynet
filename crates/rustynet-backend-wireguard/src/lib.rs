#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext,
    TunnelBackend, TunnelStats,
};

#[derive(Debug, Clone)]
pub struct WireguardBackend {
    running: bool,
    context: Option<RuntimeContext>,
    peers: BTreeMap<NodeId, PeerConfig>,
    routes: Vec<Route>,
    exit_mode: ExitMode,
    stats: TunnelStats,
}

impl Default for WireguardBackend {
    fn default() -> Self {
        Self {
            running: false,
            context: None,
            peers: BTreeMap::new(),
            routes: Vec::new(),
            exit_mode: ExitMode::Off,
            stats: TunnelStats::default(),
        }
    }
}

impl WireguardBackend {
    fn ensure_running(&self) -> Result<(), BackendError> {
        if self.running {
            return Ok(());
        }

        Err(BackendError::not_running(
            "wireguard backend is not running",
        ))
    }

    fn refresh_stats(&mut self) {
        self.stats.peer_count = self.peers.len();
    }
}

impl TunnelBackend for WireguardBackend {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: true,
            supports_exit_nodes: true,
            supports_lan_routes: true,
            supports_ipv6: true,
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        if self.running {
            return Err(BackendError::already_running(
                "wireguard backend already started",
            ));
        }

        self.context = Some(context);
        self.running = true;
        self.refresh_stats();
        Ok(())
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.peers.insert(peer.node_id.clone(), peer);
        self.refresh_stats();
        Ok(())
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.peers.remove(node_id);
        self.refresh_stats();
        Ok(())
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.routes = routes;
        Ok(())
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.exit_mode = mode;
        Ok(())
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        self.ensure_running()?;
        Ok(self.stats)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.running = false;
        self.context = None;
        self.peers.clear();
        self.routes.clear();
        self.exit_mode = ExitMode::Off;
        self.stats = TunnelStats::default();
        Ok(())
    }
}
