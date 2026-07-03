use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct VmStatus {
    pub alias: String,
    pub ip: String,
    pub platform: String,
    pub ssh_ok: bool,
}

/// Probe a single VM: TCP/22 reachability + platform inference.
pub async fn probe_vm(alias: &str, ip: &str, _utm_name: &str, ssh_user: &str) -> VmStatus {
    let ssh_ok = tcp_probe(ip, 22).await;
    let platform = infer_platform(alias, ssh_user);

    VmStatus {
        alias: alias.to_string(),
        ip: ip.to_string(),
        platform,
        ssh_ok,
    }
}

async fn tcp_probe(host: &str, port: u16) -> bool {
    let addr_str = format!("{host}:{port}");
    // Use spawn_blocking so the blocking connect_timeout doesn't stall the runtime
    tokio::task::spawn_blocking(move || {
        // Resolve first
        let addr = match addr_str.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(a) => a,
            None => return false,
        };
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
    })
    .await
    .unwrap_or(false)
}

fn infer_platform(alias: &str, ssh_user: &str) -> String {
    let key = format!("{alias} {ssh_user}").to_ascii_lowercase();
    if key.contains("windows") {
        "windows".into()
    } else if key.contains("macos") || key.contains("mac ") {
        "macos".into()
    } else {
        "linux".into()
    }
}
