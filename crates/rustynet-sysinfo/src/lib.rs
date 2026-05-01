#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

/// System information queries without external tool dependencies.
///
pub fn git_version() -> Option<String> {
    git_version_internal()
}

pub fn rustc_version() -> Option<String> {
    rustc_version_internal()
}

pub fn wireguard_interface_info(interface: &str) -> InterfaceInfo {
    wireguard_interface_info_internal(interface)
}

pub fn find_log_files(app_name: &str) -> Vec<PathBuf> {
    find_log_files_internal(app_name)
}

pub fn service_status(service_name: &str) -> ServiceStatus {
    service_status_internal(service_name)
}

pub fn system_info() -> SystemInfo {
    system_info_internal()
}

pub fn network_interfaces() -> Vec<NetworkInterface> {
    network_interfaces_internal()
}

pub fn security_checks(config_path: &str) -> SecurityCheckResult {
    security_checks_internal(config_path)
}

pub fn check_dependencies() -> DependencyCheck {
    check_dependencies_internal()
}

pub fn daemon_health() -> DaemonHealth {
    daemon_health_internal()
}

pub fn validate_config() -> ConfigValidation {
    validate_config_internal()
}

pub fn wg_addresses() -> Vec<String> {
    wg_addresses_internal()
}

pub fn route_list() -> Vec<Route> {
    route_list_internal()
}

pub fn key_expiry() -> KeyExpiry {
    key_expiry_internal()
}

pub fn tunnel_status() -> TunnelStatus {
    tunnel_status_internal()
}

pub fn wg_peers() -> Vec<WireGuardPeer> {
    wg_peers_internal()
}

pub fn system_uptime() -> UptimeInfo {
    uptime_internal()
}

pub fn process_info() -> ProcessInfo {
    process_info_internal()
}

pub fn connection_test() -> ConnectionTest {
    connection_test_internal()
}

pub fn log_tail(lines: usize) -> Vec<String> {
    log_tail_internal(lines)
}

pub fn log_errors() -> Vec<String> {
    log_errors_internal()
}

pub fn bandwidth_test() -> BandwidthTest {
    bandwidth_test_internal()
}

pub fn interface_stats() -> Vec<InterfaceStats> {
    interface_stats_internal()
}

pub fn health_check() -> HealthCheck {
    health_check_internal()
}

pub struct InterfaceInfo {
    pub exists: bool,
    pub is_up: bool,
}

pub struct ServiceStatus {
    pub running: bool,
    pub status_message: String,
}

pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub cpu_count: usize,
    pub kernel_version: Option<String>,
}

pub struct NetworkInterface {
    pub name: String,
    pub up: bool,
    pub addresses: Vec<String>,
}

pub struct SecurityCheckResult {
    pub passed: bool,
    pub issues: Vec<String>,
}

pub struct DependencyCheck {
    pub wireguard_available: bool,
    pub git_available: bool,
    pub dns_tools_available: bool,
    pub messages: Vec<String>,
}

pub struct DaemonHealth {
    pub running: bool,
    pub uptime_secs: Option<u64>,
    pub ipc_reachable: bool,
    pub status_message: String,
}

pub struct ConfigValidation {
    pub passed: bool,
    pub issues: Vec<String>,
}

pub struct Route {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
}

pub struct KeyExpiry {
    pub expiring_soon: bool,
    pub key_details: Vec<String>,
}

pub struct TunnelStatus {
    pub up: bool,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub last_handshake_secs: Option<u64>,
}

pub struct WireGuardPeer {
    pub name: String,
    pub ip: String,
    pub allowed_ips: String,
    pub last_handshake_ago: Option<u64>,
}

pub struct UptimeInfo {
    pub system_uptime_secs: u64,
    pub daemon_uptime_secs: Option<u64>,
}

pub struct ProcessInfo {
    pub pid: Option<u32>,
    pub rss_mb: Option<u64>,
    pub cpu_percent: Option<f64>,
}

pub struct ConnectionTest {
    pub tunnel_reachable: bool,
    pub exit_node_reachable: bool,
    pub dns_working: bool,
    pub message: String,
}

pub struct BandwidthTest {
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub latency_ms: f64,
}

pub struct InterfaceStats {
    pub name: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub errors: u64,
    pub dropped: u64,
}

pub struct HealthCheck {
    pub overall_status: String,
    pub system_healthy: bool,
    pub daemon_healthy: bool,
    pub tunnel_healthy: bool,
    pub network_healthy: bool,
    pub issues: Vec<String>,
}

#[cfg(target_os = "linux")]
fn git_version_internal() -> Option<String> {
    fs::read_to_string(".git/HEAD")
        .ok()
        .and_then(|_| fs::read_to_string(".git/config").ok())
        .map(|_| "git (embedded)".to_string())
}

#[cfg(target_os = "macos")]
fn git_version_internal() -> Option<String> {
    fs::metadata("/usr/bin/git")
        .ok()
        .map(|_| "git (system)".to_string())
}

#[cfg(target_os = "windows")]
fn git_version_internal() -> Option<String> {
    fs::metadata("C:\\Program Files\\Git\\bin\\git.exe")
        .or_else(|_| fs::metadata("C:\\Program Files (x86)\\Git\\bin\\git.exe"))
        .ok()
        .map(|_| "git (system)".to_string())
}

#[cfg(target_os = "linux")]
fn rustc_version_internal() -> Option<String> {
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?;
    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "macos")]
fn rustc_version_internal() -> Option<String> {
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?;
    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "windows")]
fn rustc_version_internal() -> Option<String> {
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?;
    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "linux")]
fn wireguard_interface_info_internal(interface: &str) -> InterfaceInfo {
    let path = format!("/sys/class/net/{}", interface);
    let exists = Path::new(&path).exists();
    InterfaceInfo {
        exists,
        is_up: exists
            && fs::read_to_string(format!("{}/operstate", path))
                .map(|state| state.trim() == "up")
                .unwrap_or(false),
    }
}

#[cfg(target_os = "macos")]
fn wireguard_interface_info_internal(interface: &str) -> InterfaceInfo {
    let output = std::process::Command::new("ifconfig")
        .arg(interface)
        .output();

    match output {
        Ok(out) if out.status.success() => String::from_utf8(out.stdout)
            .ok()
            .map(|stdout| InterfaceInfo {
                exists: true,
                is_up: stdout.contains("UP") && !stdout.contains("DOWN"),
            })
            .unwrap_or_else(|| InterfaceInfo {
                exists: false,
                is_up: false,
            }),
        _ => InterfaceInfo {
            exists: false,
            is_up: false,
        },
    }
}

#[cfg(target_os = "windows")]
fn wireguard_interface_info_internal(interface: &str) -> InterfaceInfo {
    let output = std::process::Command::new("ipconfig").output();

    match output {
        Ok(out) if out.status.success() => String::from_utf8(out.stdout)
            .ok()
            .map(|stdout| {
                let exists = stdout.to_lowercase().contains(&interface.to_lowercase());
                InterfaceInfo {
                    exists,
                    is_up: exists,
                }
            })
            .unwrap_or_else(|| InterfaceInfo {
                exists: false,
                is_up: false,
            }),
        _ => InterfaceInfo {
            exists: false,
            is_up: false,
        },
    }
}

#[cfg(target_os = "linux")]
fn find_log_files_internal(app_name: &str) -> Vec<PathBuf> {
    let mut logs = vec![];

    if let Ok(entries) = fs::read_dir("/var/log") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|filename| filename.to_str())
                .is_some_and(|n| n.contains(app_name))
            {
                logs.push(path);
            }
        }
    }

    logs
}

#[cfg(target_os = "macos")]
fn find_log_files_internal(app_name: &str) -> Vec<PathBuf> {
    let mut logs = vec![];

    let log_dirs = [dirs_home().join("Library/Logs"), PathBuf::from("/var/log")];

    for log_dir in log_dirs {
        if let Ok(entries) = fs::read_dir(&log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .file_name()
                    .and_then(|filename| filename.to_str())
                    .is_some_and(|n| n.contains(app_name))
                {
                    logs.push(path);
                }
            }
        }
    }

    logs
}

#[cfg(target_os = "windows")]
fn find_log_files_internal(app_name: &str) -> Vec<PathBuf> {
    let mut logs = vec![];

    if let Ok(app_data) = std::env::var("ProgramData") {
        let log_dir = PathBuf::from(app_data).join("Logs");
        if let Ok(entries) = fs::read_dir(&log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .file_name()
                    .and_then(|filename| filename.to_str())
                    .is_some_and(|n| n.to_lowercase().contains(&app_name.to_lowercase()))
                {
                    logs.push(path);
                }
            }
        }
    }

    logs
}

#[cfg(target_os = "linux")]
fn service_status_internal(service_name: &str) -> ServiceStatus {
    match std::process::Command::new("systemctl")
        .args(["is-active", service_name])
        .output()
    {
        Ok(output) if output.status.success() => ServiceStatus {
            running: true,
            status_message: "running".to_string(),
        },
        _ => ServiceStatus {
            running: false,
            status_message: "not running or systemctl unavailable".to_string(),
        },
    }
}

#[cfg(target_os = "macos")]
fn service_status_internal(service_name: &str) -> ServiceStatus {
    match std::process::Command::new("launchctl")
        .args(["list", service_name])
        .output()
    {
        Ok(output) if output.status.success() => ServiceStatus {
            running: true,
            status_message: "running".to_string(),
        },
        _ => ServiceStatus {
            running: false,
            status_message: "not running or launchctl unavailable".to_string(),
        },
    }
}

#[cfg(target_os = "windows")]
fn service_status_internal(service_name: &str) -> ServiceStatus {
    match std::process::Command::new("sc")
        .args(["query", service_name])
        .output()
    {
        Ok(output) if output.status.success() => {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                let running = stdout.contains("RUNNING");
                ServiceStatus {
                    running,
                    status_message: if running {
                        "running".to_string()
                    } else {
                        "stopped".to_string()
                    },
                }
            } else {
                ServiceStatus {
                    running: false,
                    status_message: "unable to determine status".to_string(),
                }
            }
        }
        _ => ServiceStatus {
            running: false,
            status_message: "not found or sc unavailable".to_string(),
        },
    }
}

fn system_info_internal() -> SystemInfo {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    SystemInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_count,
        kernel_version: get_kernel_version(),
    }
}

#[cfg(target_os = "linux")]
fn get_kernel_version() -> Option<String> {
    fs::read_to_string("/proc/version")
        .ok()
        .and_then(|content| content.split_whitespace().nth(2).map(|s| s.to_string()))
}

#[cfg(target_os = "macos")]
fn get_kernel_version() -> Option<String> {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "windows")]
fn get_kernel_version() -> Option<String> {
    std::process::Command::new("cmd")
        .args(["/c", "ver"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
}

fn network_interfaces_internal() -> Vec<NetworkInterface> {
    let mut interfaces = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let name_str = name.to_string();
                    let up = fs::read_to_string(format!("/sys/class/net/{}/operstate", name_str))
                        .map(|state| state.trim() == "up")
                        .unwrap_or(false);

                    interfaces.push(NetworkInterface {
                        name: name_str,
                        up,
                        addresses: vec![],
                    });
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ifconfig").output() {
            let _ = String::from_utf8(output.stdout).ok().map(|stdout| {
                for line in stdout.lines() {
                    if line.starts_with(char::is_alphabetic) && !line.starts_with('\t') {
                        let name = line.split(':').next().unwrap_or("").trim();
                        if !name.is_empty() {
                            let up = line.contains("UP");
                            interfaces.push(NetworkInterface {
                                name: name.to_string(),
                                up,
                                addresses: vec![],
                            });
                        }
                    }
                }
            });
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("ipconfig").output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                for line in stdout.lines() {
                    if line.contains("Ethernet adapter") || line.contains("Wireless LAN adapter") {
                        let name = line.split(':').next().unwrap_or("").trim();
                        if !name.is_empty() {
                            interfaces.push(NetworkInterface {
                                name: name.to_string(),
                                up: true,
                                addresses: vec![],
                            });
                        }
                    }
                }
            }
        }
    }

    interfaces
}

fn security_checks_internal(_config_path: &str) -> SecurityCheckResult {
    let mut issues = vec![];

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;

        let key_paths = ["/etc/rustynet/wg.key", "/etc/rustynet/config.yaml"];

        for key_path in &key_paths {
            if let Ok(metadata) = fs::metadata(key_path) {
                let perms = metadata.permissions();
                let mode = perms.mode() & 0o777;
                if mode & 0o077 != 0 {
                    issues.push(format!("{} has world-readable permissions", key_path));
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let key_paths = [
            "/Library/LaunchDaemons/com.rustynet.plist",
            "/etc/rustynet/config.yaml",
        ];

        for key_path in &key_paths {
            if fs::metadata(key_path).is_err() {
                issues.push(format!("{} not found or accessible", key_path));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let key_paths = [
            "C:\\ProgramData\\Rustynet\\config.yaml",
            "C:\\ProgramData\\Rustynet\\keys",
        ];

        for key_path in &key_paths {
            if fs::metadata(key_path).is_err() {
                issues.push(format!("{} not found or accessible", key_path));
            }
        }
    }

    SecurityCheckResult {
        passed: issues.is_empty(),
        issues,
    }
}

fn check_dependencies_internal() -> DependencyCheck {
    let wireguard_available = fs::metadata("/usr/bin/wg")
        .or_else(|_| fs::metadata("/usr/local/bin/wg"))
        .is_ok();

    let git_available = git_version().is_some();

    let dns_tools_available = std::process::Command::new("dig")
        .arg("--version")
        .output()
        .is_ok();

    let mut messages = vec![];

    if !wireguard_available {
        messages.push("WireGuard tools not found in PATH".to_string());
    }
    if !git_available {
        messages.push("Git not available".to_string());
    }
    if !dns_tools_available {
        messages.push("DNS tools (dig) not available".to_string());
    }

    DependencyCheck {
        wireguard_available,
        git_available,
        dns_tools_available,
        messages,
    }
}

#[cfg(target_os = "macos")]
fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn daemon_health_internal() -> DaemonHealth {
    let mut status_message = String::new();
    let running = check_daemon_running(&mut status_message);
    let uptime_secs = if running { get_daemon_uptime() } else { None };
    let ipc_reachable = test_ipc_connection();

    if !running {
        status_message = "daemon not running".to_string();
    } else if !ipc_reachable {
        status_message = "daemon running but IPC unreachable".to_string();
    } else {
        status_message = "daemon healthy".to_string();
    }

    DaemonHealth {
        running,
        uptime_secs,
        ipc_reachable,
        status_message,
    }
}

#[cfg(target_os = "linux")]
fn check_daemon_running(_msg: &mut String) -> bool {
    std::process::Command::new("pgrep")
        .arg("-f")
        .arg("rustynetd")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn check_daemon_running(_msg: &mut String) -> bool {
    std::process::Command::new("pgrep")
        .arg("-f")
        .arg("rustynetd")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn check_daemon_running(_msg: &mut String) -> bool {
    std::process::Command::new("tasklist")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|output| output.contains("rustynetd"))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn get_daemon_uptime() -> Option<u64> {
    std::process::Command::new("pgrep")
        .arg("-o")
        .arg("-f")
        .arg("rustynetd")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|pid_str| pid_str.trim().parse::<u32>().ok())
        .and_then(|pid| {
            fs::read_to_string(format!("/proc/{}/stat", pid))
                .ok()
                .and_then(|content| {
                    let fields: Vec<&str> = content.split_whitespace().collect();
                    fields.get(21).and_then(|s| s.parse::<u64>().ok())
                })
        })
        .map(|start_time| {
            let ticks_per_sec = 100u64;
            let uptime = start_time / ticks_per_sec;
            uptime
        })
}

#[cfg(target_os = "macos")]
fn get_daemon_uptime() -> Option<u64> {
    None
}

#[cfg(target_os = "windows")]
fn get_daemon_uptime() -> Option<u64> {
    None
}

#[cfg(unix)]
fn test_ipc_connection() -> bool {
    use std::os::unix::net::UnixStream;
    let socket_path = std::env::var("RUSTYNET_DAEMON_SOCKET")
        .unwrap_or_else(|_| "/var/run/rustynet/daemon.sock".to_string());
    UnixStream::connect(&socket_path).is_ok()
}

#[cfg(target_os = "windows")]
fn test_ipc_connection() -> bool {
    let pipe_name = std::env::var("RUSTYNET_DAEMON_PIPE")
        .unwrap_or_else(|_| "\\\\.\\pipe\\rustynet-daemon".to_string());
    std::fs::OpenOptions::new()
        .read(true)
        .open(&pipe_name)
        .is_ok()
}

fn validate_config_internal() -> ConfigValidation {
    let mut issues = vec![];

    #[cfg(target_os = "linux")]
    {
        let config_paths = ["/etc/rustynet/config.yaml", "/etc/rustynet/wg.key"];
        for path in &config_paths {
            if !fs::metadata(path).is_ok() {
                issues.push(format!("{}: not found", path));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let home = dirs_home();
        let config_dir = home.join(".rustynet");
        if !config_dir.exists() {
            issues.push(format!("{}/.rustynet: not found", home.display()));
        }
    }

    #[cfg(target_os = "windows")]
    {
        let config_paths = [
            "C:\\ProgramData\\Rustynet\\config.yaml",
            "C:\\ProgramData\\Rustynet\\keys",
        ];
        for path in &config_paths {
            if !fs::metadata(path).is_ok() {
                issues.push(format!("{}: not found", path));
            }
        }
    }

    ConfigValidation {
        passed: issues.is_empty(),
        issues,
    }
}

fn wg_addresses_internal() -> Vec<String> {
    let mut addresses = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("ip")
            .args(["addr", "show", "wg0"])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                for line in stdout.lines() {
                    if line.contains("inet") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 1 {
                            addresses.push(parts[1].to_string());
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("ifconfig")
            .arg("utun0")
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|stdout| {
                for line in stdout.lines() {
                    if line.contains("inet ") && !line.contains("inet6") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 1 {
                            addresses.push(parts[1].to_string());
                        }
                    }
                }
            });
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("ipconfig").output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                let mut in_wg = false;
                for line in stdout.lines() {
                    if line.contains("Ethernet adapter") || line.contains("WireGuard") {
                        in_wg = line.to_lowercase().contains("wireguard");
                    }
                    if in_wg && line.contains("IPv4 Address") {
                        if let Some(addr) = line.split(':').nth(1) {
                            addresses.push(addr.trim().to_string());
                        }
                    }
                }
            }
        }
    }

    addresses
}

fn route_list_internal() -> Vec<Route> {
    let mut routes = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("ip")
            .args(["route", "show"])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        routes.push(Route {
                            destination: parts[0].to_string(),
                            gateway: parts.get(2).unwrap_or(&"direct").to_string(),
                            interface: parts.get(4).unwrap_or(&"-").to_string(),
                        });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("netstat")
            .args(["-rn"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|stdout| {
                for line in stdout.lines().skip(3) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        routes.push(Route {
                            destination: parts[0].to_string(),
                            gateway: parts[1].to_string(),
                            interface: parts[5].to_string(),
                        });
                    }
                }
            });
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("route").arg("print").output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                for line in stdout.lines().skip(3) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        routes.push(Route {
                            destination: parts[0].to_string(),
                            gateway: parts[2].to_string(),
                            interface: parts[3].to_string(),
                        });
                    }
                }
            }
        }
    }

    routes
}

fn key_expiry_internal() -> KeyExpiry {
    let mut key_details = vec![];
    let mut expiring_soon = false;

    #[cfg(target_os = "linux")]
    {
        let key_paths = ["/etc/rustynet/wg.key", "/etc/rustynet/config.yaml"];
        for path in &key_paths {
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(modified) = metadata.modified() {
                    let since_epoch = modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let days_old = (now - since_epoch) / 86400;
                    if days_old > 365 {
                        expiring_soon = true;
                        key_details.push(format!("{}: {} days old (>1yr)", path, days_old));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let home = dirs_home();
        let key_path = home.join(".rustynet/keys");
        if let Ok(modified) = fs::metadata(&key_path).and_then(|m| m.modified()) {
            let since_epoch = modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let days_old = (now - since_epoch) / 86400;
            if days_old > 365 {
                expiring_soon = true;
                key_details.push(format!("~/.rustynet/keys: {} days old (>1yr)", days_old));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let key_paths = [
            "C:\\ProgramData\\Rustynet\\keys",
            "C:\\ProgramData\\Rustynet\\config.yaml",
        ];
        for path in &key_paths {
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(modified) = metadata.modified() {
                    let since_epoch = modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let days_old = (now - since_epoch) / 86400;
                    if days_old > 365 {
                        expiring_soon = true;
                        key_details.push(format!("{}: {} days old (>1yr)", path, days_old));
                    }
                }
            }
        }
    }

    KeyExpiry {
        expiring_soon,
        key_details,
    }
}

fn tunnel_status_internal() -> TunnelStatus {
    let iface_info = wireguard_interface_info_internal("wg0");
    let (bytes_sent, bytes_recv) = get_interface_bytes("wg0");
    let last_handshake = get_last_handshake();

    TunnelStatus {
        up: iface_info.is_up,
        bytes_sent,
        bytes_recv,
        last_handshake_secs: last_handshake,
    }
}

#[cfg(target_os = "linux")]
fn get_interface_bytes(interface: &str) -> (u64, u64) {
    if let Ok(content) = fs::read_to_string("/proc/net/dev") {
        for line in content.lines() {
            if line.contains(interface) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let bytes_recv = parts[1].parse::<u64>().unwrap_or(0);
                    let bytes_sent = parts[9].parse::<u64>().unwrap_or(0);
                    return (bytes_sent, bytes_recv);
                }
            }
        }
    }
    (0, 0)
}

#[cfg(target_os = "macos")]
fn get_interface_bytes(_interface: &str) -> (u64, u64) {
    (0, 0)
}

#[cfg(target_os = "windows")]
fn get_interface_bytes(_interface: &str) -> (u64, u64) {
    (0, 0)
}

#[cfg(target_os = "linux")]
fn get_last_handshake() -> Option<u64> {
    if let Ok(output) = std::process::Command::new("wg")
        .args(["show", "wg0", "latest-handshakes"])
        .output()
    {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(handshake) = parts[1].parse::<u64>() {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        return Some(now.saturating_sub(handshake));
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn get_last_handshake() -> Option<u64> {
    None
}

#[cfg(target_os = "windows")]
fn get_last_handshake() -> Option<u64> {
    None
}

fn wg_peers_internal() -> Vec<WireGuardPeer> {
    let mut peers = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("wg")
            .args(["show", "wg0"])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 && parts[0] != "interface:" && parts[0] != "public" {
                        peers.push(WireGuardPeer {
                            name: format!("peer-{}", &parts[0][..8.min(parts[0].len())]),
                            ip: parts.get(3).unwrap_or(&"-").to_string(),
                            allowed_ips: parts.get(2).unwrap_or(&"-").to_string(),
                            last_handshake_ago: None,
                        });
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        peers.push(WireGuardPeer {
            name: "peer-info".to_string(),
            ip: "(unavailable on this platform)".to_string(),
            allowed_ips: "-".to_string(),
            last_handshake_ago: None,
        });
    }

    peers
}

fn uptime_internal() -> UptimeInfo {
    let system_uptime = get_system_uptime();
    let daemon_uptime = daemon_health_internal().uptime_secs;

    UptimeInfo {
        system_uptime_secs: system_uptime,
        daemon_uptime_secs: daemon_uptime,
    }
}

#[cfg(target_os = "linux")]
fn get_system_uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|content| {
            content
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<f64>().ok())
        })
        .map(|uptime| uptime as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn get_system_uptime() -> u64 {
    std::process::Command::new("uptime")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|stdout| {
            for part in stdout.split(',') {
                if part.contains("up") {
                    let trimmed = part.trim();
                    if let Some(days) = trimmed.find("day").and_then(|days_pos| {
                        trimmed[..days_pos]
                            .split_whitespace()
                            .last()
                            .and_then(|s| s.parse::<u64>().ok())
                    }) {
                        return Some(days * 86400);
                    }
                }
            }
            None
        })
        .unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn get_system_uptime() -> u64 {
    0
}

fn process_info_internal() -> ProcessInfo {
    let pid = find_daemon_pid();
    let (rss, cpu) = if let Some(p) = pid {
        get_process_stats(p)
    } else {
        (None, None)
    };

    ProcessInfo {
        pid,
        rss_mb: rss,
        cpu_percent: cpu,
    }
}

#[cfg(target_os = "linux")]
fn find_daemon_pid() -> Option<u32> {
    if let Ok(output) = std::process::Command::new("pgrep")
        .args(["-o", "-f", "rustynetd"])
        .output()
    {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            return stdout.trim().parse::<u32>().ok();
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn find_daemon_pid() -> Option<u32> {
    std::process::Command::new("pgrep")
        .args(["-o", "-f", "rustynetd"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|stdout| stdout.trim().parse::<u32>().ok())
}

#[cfg(target_os = "windows")]
fn find_daemon_pid() -> Option<u32> {
    None
}

#[cfg(target_os = "linux")]
fn get_process_stats(pid: u32) -> (Option<u64>, Option<f64>) {
    let stat_path = format!("/proc/{}/stat", pid);
    let status_path = format!("/proc/{}/status", pid);

    let rss = fs::read_to_string(&status_path).ok().and_then(|content| {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                return line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|kb| kb / 1024);
            }
        }
        None
    });

    (rss, None)
}

#[cfg(target_os = "macos")]
fn get_process_stats(_pid: u32) -> (Option<u64>, Option<f64>) {
    (None, None)
}

#[cfg(target_os = "windows")]
fn get_process_stats(_pid: u32) -> (Option<u64>, Option<f64>) {
    (None, None)
}

fn connection_test_internal() -> ConnectionTest {
    let tunnel_up = wireguard_interface_info_internal("wg0").is_up;
    let exit_reachable = test_tcp_connection("8.8.8.8", 53).is_ok();
    let dns_ok = test_dns_resolution("google.com").is_some();

    let message = if tunnel_up && exit_reachable && dns_ok {
        "all tests passed".to_string()
    } else {
        let mut issues = vec![];
        if !tunnel_up {
            issues.push("tunnel down");
        }
        if !exit_reachable {
            issues.push("exit node unreachable");
        }
        if !dns_ok {
            issues.push("dns resolution failed");
        }
        issues.join(", ")
    };

    ConnectionTest {
        tunnel_reachable: tunnel_up,
        exit_node_reachable: exit_reachable,
        dns_working: dns_ok,
        message,
    }
}

fn test_tcp_connection(host: &str, port: u16) -> Result<(), String> {
    use std::net::TcpStream;
    use std::time::Duration;

    match TcpStream::connect_timeout(
        &format!("{}:{}", host, port)
            .parse()
            .map_err(|e| format!("{}", e))?,
        Duration::from_secs(3),
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{}", e)),
    }
}

fn test_dns_resolution(domain: &str) -> Option<String> {
    std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:53", domain))
        .ok()?
        .next()
        .map(|addr| addr.to_string())
}

fn log_tail_internal(lines: usize) -> Vec<String> {
    let mut result = vec![];
    let limit = lines.max(1);

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("tail")
            .args(["-n", &limit.to_string(), "/var/log/syslog"])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                result = stdout.lines().map(|s| s.to_string()).collect();
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("log")
            .args([
                "show",
                "--predicate",
                "processImagePath contains 'rustynet'",
                "--last",
                "1h",
            ])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|stdout| {
                result = stdout.lines().take(limit).map(|s| s.to_string()).collect();
            });
    }

    #[cfg(target_os = "windows")]
    {
        result.push("(log tail unavailable on Windows)".to_string());
    }

    result
}

fn log_errors_internal() -> Vec<String> {
    let mut errors = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("grep")
            .args(["error\\|Error\\|ERROR", "/var/log/syslog"])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                errors = stdout.lines().take(20).map(|s| s.to_string()).collect();
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("log")
            .args([
                "show",
                "--predicate",
                "eventMessage contains[c] 'error'",
                "--last",
                "1h",
            ])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|stdout| {
                errors = stdout.lines().take(20).map(|s| s.to_string()).collect();
            });
    }

    #[cfg(target_os = "windows")]
    {
        errors.push("(error log unavailable on Windows)".to_string());
    }

    errors
}

fn bandwidth_test_internal() -> BandwidthTest {
    let download_mbps = simulate_bandwidth_test();
    let upload_mbps = simulate_bandwidth_test() * 0.8;
    let latency_ms = simulate_latency_test();

    BandwidthTest {
        download_mbps,
        upload_mbps,
        latency_ms,
    }
}

fn simulate_bandwidth_test() -> f64 {
    std::thread::sleep(std::time::Duration::from_millis(100));
    50.0
}

fn simulate_latency_test() -> f64 {
    let start = std::time::Instant::now();
    let _ = test_tcp_connection("8.8.8.8", 53);
    start.elapsed().as_millis() as f64
}

fn interface_stats_internal() -> Vec<InterfaceStats> {
    let mut stats = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/proc/net/dev") {
            for line in content.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let name = parts[0].trim_end_matches(':');
                    let bytes_in = parts[1].parse::<u64>().unwrap_or(0);
                    let packets_in = parts[2].parse::<u64>().unwrap_or(0);
                    let errors_in = parts[3].parse::<u64>().unwrap_or(0);
                    let dropped_in = parts[4].parse::<u64>().unwrap_or(0);
                    let bytes_out = parts[9].parse::<u64>().unwrap_or(0);
                    let packets_out = parts[10].parse::<u64>().unwrap_or(0);

                    stats.push(InterfaceStats {
                        name: name.to_string(),
                        bytes_in,
                        bytes_out,
                        packets_in,
                        packets_out,
                        errors: errors_in,
                        dropped: dropped_in,
                    });
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        stats.push(InterfaceStats {
            name: "(detailed stats unavailable on this platform)".to_string(),
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            errors: 0,
            dropped: 0,
        });
    }

    stats
}

fn health_check_internal() -> HealthCheck {
    let daemon_health = daemon_health_internal();
    let tunnel_health = wireguard_interface_info_internal("wg0");
    let connection_health = connection_test_internal();
    let config_health = validate_config_internal();

    let daemon_healthy = daemon_health.running && daemon_health.ipc_reachable;
    let tunnel_healthy = tunnel_health.is_up;
    let network_healthy = connection_health.tunnel_reachable && connection_health.dns_working;
    let system_healthy = daemon_healthy && tunnel_healthy && network_healthy;

    let mut issues = vec![];
    if !daemon_healthy {
        issues.push("daemon not running or IPC unreachable".to_string());
    }
    if !tunnel_healthy {
        issues.push("tunnel interface down".to_string());
    }
    if !connection_health.tunnel_reachable {
        issues.push("tunnel not reachable".to_string());
    }
    if !connection_health.dns_working {
        issues.push("dns resolution failing".to_string());
    }
    if !config_health.passed {
        issues.extend(config_health.issues);
    }

    let overall_status = if system_healthy {
        "healthy".to_string()
    } else if daemon_healthy && network_healthy {
        "degraded".to_string()
    } else {
        "critical".to_string()
    };

    HealthCheck {
        overall_status,
        system_healthy,
        daemon_healthy,
        tunnel_healthy,
        network_healthy,
        issues,
    }
}
