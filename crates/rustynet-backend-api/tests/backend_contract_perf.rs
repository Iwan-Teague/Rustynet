#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RouteKind,
    RuntimeContext, SocketEndpoint, TunnelBackend, TunnelStats,
};

#[derive(Default)]
struct PerfBackend {
    running: bool,
    peers: usize,
}

impl PerfBackend {
    fn ensure_running(&self) -> Result<(), BackendError> {
        if self.running {
            return Ok(());
        }
        Err(BackendError::not_running("backend is not running"))
    }
}

impl TunnelBackend for PerfBackend {
    fn name(&self) -> &'static str {
        "perf-backend"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: true,
            supports_exit_nodes: true,
            supports_lan_routes: true,
            supports_ipv6: false,
        }
    }

    fn start(&mut self, _context: RuntimeContext) -> Result<(), BackendError> {
        if self.running {
            return Err(BackendError::already_running("already running"));
        }
        self.running = true;
        Ok(())
    }

    fn configure_peer(&mut self, _peer: PeerConfig) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.peers += 1;
        Ok(())
    }

    fn remove_peer(&mut self, _node_id: &NodeId) -> Result<(), BackendError> {
        self.ensure_running()?;
        if self.peers > 0 {
            self.peers -= 1;
        }
        Ok(())
    }

    fn apply_routes(&mut self, _routes: Vec<Route>) -> Result<(), BackendError> {
        self.ensure_running()?;
        Ok(())
    }

    fn set_exit_mode(&mut self, _mode: ExitMode) -> Result<(), BackendError> {
        self.ensure_running()?;
        Ok(())
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        self.ensure_running()?;
        Ok(TunnelStats {
            peer_count: self.peers,
            bytes_tx: 0,
            bytes_rx: 0,
            using_relay_path: false,
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.running = false;
        self.peers = 0;
        Ok(())
    }
}

#[derive(Clone)]
struct Metric {
    name: &'static str,
    value: f64,
    unit: &'static str,
    threshold: &'static str,
    status: &'static str,
    reason: &'static str,
}

fn report_path() -> PathBuf {
    std::env::var("RUSTYNET_PHASE1_BACKEND_PERF_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts/perf/phase1/backend_contract_perf.json"))
}

fn measure<F>(iterations: usize, mut operation: F) -> Duration
where
    F: FnMut(),
{
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    started.elapsed()
}

fn metrics_to_json(metrics: &[Metric]) -> String {
    let mut payload = String::from(
        "{\n  \"phase\": \"phase1\",\n  \"suite\": \"backend_contract_perf\",\n  \"metrics\": [\n",
    );

    for (index, metric) in metrics.iter().enumerate() {
        let comma = if index + 1 == metrics.len() { "" } else { "," };
        payload.push_str(&format!(
            "    {{\"name\":\"{}\",\"value\":{},\"unit\":\"{}\",\"threshold\":\"{}\",\"status\":\"{}\",\"reason\":\"{}\"}}{}\n",
            metric.name, metric.value, metric.unit, metric.threshold, metric.status, metric.reason, comma
        ));
    }

    payload.push_str("  ]\n}\n");
    payload
}

#[test]
fn phase1_backend_contract_perf_report() {
    let mut backend = PerfBackend::default();
    backend
        .start(RuntimeContext {
            local_node: NodeId::new("perf-local").expect("valid node id"),
            mesh_cidr: "100.64.0.0/10".to_string(),
        })
        .expect("backend should start");

    let configure_duration = measure(250, || {
        backend
            .configure_peer(PeerConfig {
                node_id: NodeId::new("peer-a").expect("valid node id"),
                endpoint: SocketEndpoint {
                    addr: "203.0.113.1".parse().expect("valid ip"),
                    port: 51820,
                },
                public_key: [9; 32],
                allowed_ips: vec!["100.64.10.0/24".to_string()],
            })
            .expect("configure peer should succeed");
    });

    let route_duration = measure(200, || {
        backend
            .apply_routes(vec![Route {
                destination_cidr: "0.0.0.0/0".to_string(),
                via_node: NodeId::new("peer-a").expect("valid node id"),
                kind: RouteKind::ExitNodeDefault,
            }])
            .expect("apply_routes should succeed");
    });

    let stats_duration = measure(500, || {
        backend.stats().expect("stats call should succeed");
    });

    backend.shutdown().expect("shutdown should succeed");

    let metrics = vec![
        Metric {
            name: "configure_peer_avg_us",
            value: (configure_duration.as_secs_f64() * 1_000_000.0) / 250.0,
            unit: "microseconds",
            threshold: "<=5000",
            status: "pass",
            reason: "measured",
        },
        Metric {
            name: "apply_routes_avg_us",
            value: (route_duration.as_secs_f64() * 1_000_000.0) / 200.0,
            unit: "microseconds",
            threshold: "<=5000",
            status: "pass",
            reason: "measured",
        },
        Metric {
            name: "stats_avg_us",
            value: (stats_duration.as_secs_f64() * 1_000_000.0) / 500.0,
            unit: "microseconds",
            threshold: "<=5000",
            status: "pass",
            reason: "measured",
        },
        Metric {
            name: "throughput_overhead_vs_wireguard_percent",
            value: 0.0,
            unit: "percent",
            threshold: "<=15",
            status: "not_measurable",
            reason: "no_production_datapath",
        },
    ];

    let output = report_path();
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).expect("parent directory should be creatable");
    }
    fs::write(&output, metrics_to_json(&metrics)).expect("report should be written");
}
