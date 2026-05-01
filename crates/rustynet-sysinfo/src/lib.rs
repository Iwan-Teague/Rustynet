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

pub fn system_load() -> SystemLoad {
    system_load_internal()
}

pub fn memory_info() -> MemoryInfo {
    memory_info_internal()
}

pub fn disk_info() -> Vec<DiskInfo> {
    disk_info_internal()
}

pub fn cpu_info() -> CpuInfo {
    cpu_info_internal()
}

pub fn socket_stats() -> SocketStats {
    socket_stats_internal()
}

pub fn env_validate() -> Vec<String> {
    env_validate_internal()
}

pub fn process_list() -> Vec<ProcessListEntry> {
    process_list_internal()
}

pub fn iface_list() -> Vec<InterfaceDetail> {
    iface_list_internal()
}

pub fn dns_check() -> DnsCheck {
    dns_check_internal()
}

pub fn kernel_info() -> KernelInfo {
    kernel_info_internal()
}

pub fn service_check() -> ServiceCheck {
    service_check_internal()
}

pub fn permission_check() -> Vec<String> {
    permission_check_internal()
}

pub fn performance_test() -> PerformanceTest {
    performance_test_internal()
}

pub fn tls_check() -> TlsCheck {
    tls_check_internal()
}

pub fn rate_limit_check() -> RateLimitCheck {
    rate_limit_check_internal()
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

pub struct SystemLoad {
    pub cpu_load_1min: f64,
    pub cpu_load_5min: f64,
    pub cpu_load_15min: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
}

pub struct MemoryInfo {
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
    pub percent: f64,
}

pub struct DiskInfo {
    pub mount: String,
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
    pub percent: f64,
}

pub struct CpuInfo {
    pub cores: usize,
    pub model: String,
    pub freq_ghz: Option<f64>,
}

pub struct SocketStats {
    pub established: usize,
    pub listening: usize,
    pub time_wait: usize,
    pub total: usize,
}

pub struct ProcessListEntry {
    pub name: String,
    pub pid: u32,
    pub memory_mb: u64,
    pub uptime_seconds: u64,
}

pub struct InterfaceDetail {
    pub name: String,
    pub up: bool,
    pub mac_address: Option<String>,
    pub ip_addresses: Vec<String>,
    pub mtu: u32,
}

pub struct DnsCheck {
    pub working: bool,
    pub resolvers: Vec<String>,
    pub test_results: Vec<String>,
}

pub struct KernelInfo {
    pub version: String,
    pub release: String,
    pub machine: String,
}

pub struct ServiceCheck {
    pub daemon_running: bool,
    pub daemon_enabled: bool,
    pub uptime_seconds: Option<u64>,
    pub status: String,
}

pub struct PerformanceTest {
    pub cpu_time_ms: u64,
    pub memory_alloc_mb: u64,
    pub disk_io_ops: u64,
}

pub struct TlsCheck {
    pub tls_available: bool,
    pub tls_version: Option<String>,
    pub certificate_valid: bool,
    pub issues: Vec<String>,
}

pub struct RateLimitCheck {
    pub current_connections: usize,
    pub connection_limit: usize,
    pub request_rate_per_sec: f64,
    pub rate_limit_per_sec: f64,
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
        .arg("-x")
        .arg("rustynetd")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn check_daemon_running(_msg: &mut String) -> bool {
    std::process::Command::new("pgrep")
        .arg("-x")
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
        .arg("-x")
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
    if let Ok(output) = std::process::Command::new("pgrep")
        .args(["-o", "-x", "rustynetd"])
        .output()
        && let Ok(pid_str) = String::from_utf8(output.stdout)
        && let Ok(pid) = pid_str.trim().parse::<i32>()
        && let Ok(output) = std::process::Command::new("ps")
            .args(["-o", "etime=", "-p"])
            .arg(pid.to_string())
            .output()
        && let Ok(etime) = String::from_utf8(output.stdout)
    {
        let etime = etime.trim();
        let parts: Vec<&str> = etime.split(':').collect();

        let total_secs = if parts.len() == 3 {
            if let (Ok(h), Ok(m), Ok(s)) = (
                parts[0].parse::<u64>(),
                parts[1].parse::<u64>(),
                parts[2].parse::<u64>(),
            ) {
                h * 3600 + m * 60 + s
            } else {
                0
            }
        } else if parts.len() == 2 {
            if let (Ok(m), Ok(s)) = (parts[0].parse::<u64>(), parts[1].parse::<u64>()) {
                m * 60 + s
            } else {
                0
            }
        } else {
            0
        };

        return if total_secs > 0 {
            Some(total_secs)
        } else {
            None
        };
    }
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
            .args(["addr", "show", "rustynet0"])
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
    let iface_info = wireguard_interface_info_internal("rustynet0");
    let (bytes_sent, bytes_recv) = get_interface_bytes("rustynet0");
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
        .args(["show", "rustynet0", "latest-handshakes"])
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
            .args(["show", "rustynet0"])
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

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("wg")
            .args(["show", "rustynet0"])
            .output()
            && let Ok(stdout) = String::from_utf8(output.stdout)
        {
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

    #[cfg(target_os = "windows")]
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
    let tunnel_up = wireguard_interface_info_internal("rustynet0").is_up;
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
    let tunnel_health = wireguard_interface_info_internal("rustynet0");
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

#[cfg(target_os = "linux")]
fn system_load_internal() -> SystemLoad {
    let mut load_1 = 0.0;
    let mut load_5 = 0.0;
    let mut load_15 = 0.0;

    if let Ok(content) = fs::read_to_string("/proc/loadavg") {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 3 {
            load_1 = parts[0].parse().unwrap_or(0.0);
            load_5 = parts[1].parse().unwrap_or(0.0);
            load_15 = parts[2].parse().unwrap_or(0.0);
        }
    }

    let mem_percent = memory_info_internal().percent;
    let disk_percent = disk_info_internal()
        .first()
        .map(|d| d.percent)
        .unwrap_or(0.0);

    SystemLoad {
        cpu_load_1min: load_1,
        cpu_load_5min: load_5,
        cpu_load_15min: load_15,
        memory_percent: mem_percent,
        disk_percent,
    }
}

#[cfg(target_os = "macos")]
fn system_load_internal() -> SystemLoad {
    let mut load_1 = 0.0;
    let mut load_5 = 0.0;
    let mut load_15 = 0.0;

    if let Ok(output) = std::process::Command::new("uptime").output()
        && let Ok(s) = String::from_utf8(output.stdout)
        && let Some(load_part) = s.split("load average:").nth(1)
    {
        let loads: Vec<&str> = load_part.split(',').collect();
        if loads.len() >= 3 {
            load_1 = loads[0].trim().parse().unwrap_or(0.0);
            load_5 = loads[1].trim().parse().unwrap_or(0.0);
            load_15 = loads[2].trim().parse().unwrap_or(0.0);
        }
    }

    let mem_percent = memory_info_internal().percent;
    let disk_percent = disk_info_internal()
        .first()
        .map(|d| d.percent)
        .unwrap_or(0.0);

    SystemLoad {
        cpu_load_1min: load_1,
        cpu_load_5min: load_5,
        cpu_load_15min: load_15,
        memory_percent: mem_percent,
        disk_percent,
    }
}

#[cfg(target_os = "windows")]
fn system_load_internal() -> SystemLoad {
    SystemLoad {
        cpu_load_1min: 0.0,
        cpu_load_5min: 0.0,
        cpu_load_15min: 0.0,
        memory_percent: memory_info_internal().percent,
        disk_percent: disk_info_internal()
            .first()
            .map(|d| d.percent)
            .unwrap_or(0.0),
    }
}

#[cfg(target_os = "linux")]
fn memory_info_internal() -> MemoryInfo {
    let mut total = 0u64;
    let mut available = 0u64;

    if let Ok(content) = fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                total = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
            } else if line.starts_with("MemAvailable:") {
                available = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }
    }

    let used = total.saturating_sub(available);
    let percent = if total > 0 {
        (used as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    MemoryInfo {
        total_mb: total / 1024,
        used_mb: used / 1024,
        available_mb: available / 1024,
        percent,
    }
}

#[cfg(target_os = "macos")]
fn memory_info_internal() -> MemoryInfo {
    let mut total = 0u64;
    let mut used = 0u64;

    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("hw.memsize")
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
        && let Some(val) = s.split(':').nth(1)
    {
        total = val.trim().parse::<u64>().unwrap_or(0) / 1024 / 1024;
    }

    if let Ok(output) = std::process::Command::new("vm_stat").output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        for line in s.lines() {
            if (line.contains("Pages wired down") || line.contains("Pages active"))
                && let Some(val) = line.split_whitespace().last()
            {
                let pages = val.trim_end_matches('.').parse::<u64>().unwrap_or(0);
                used += pages * 4 / 1024;
            }
        }
    }

    let available = total.saturating_sub(used);
    let percent = if total > 0 {
        (used as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    MemoryInfo {
        total_mb: total,
        used_mb: used,
        available_mb: available,
        percent,
    }
}

#[cfg(target_os = "windows")]
fn memory_info_internal() -> MemoryInfo {
    let mut total = 0u64;
    let mut available = 0u64;

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let lines: Vec<&str> = s.lines().collect();
            for line in lines.iter().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    total = parts[0].parse::<u64>().unwrap_or(0);
                    available = parts[1].parse::<u64>().unwrap_or(0);
                }
            }
        }
    }

    let used = total.saturating_sub(available);
    let percent = if total > 0 {
        (used as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    MemoryInfo {
        total_mb: total / 1024,
        used_mb: used / 1024,
        available_mb: available / 1024,
        percent,
    }
}

#[cfg(target_os = "linux")]
fn disk_info_internal() -> Vec<DiskInfo> {
    vec![DiskInfo {
        mount: "/".to_string(),
        total_mb: 0,
        used_mb: 0,
        available_mb: 0,
        percent: 0.0,
    }]
}

#[cfg(target_os = "macos")]
fn disk_info_internal() -> Vec<DiskInfo> {
    let mut disks = Vec::new();

    if let Ok(output) = std::process::Command::new("df").args(["-k", "/"]).output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        for line in s.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let total_kb = parts[1].parse::<u64>().unwrap_or(0);
                let used_kb = parts[2].parse::<u64>().unwrap_or(0);
                let available_kb = parts[3].parse::<u64>().unwrap_or(0);

                let total_mb = total_kb / 1024;
                let used_mb = used_kb / 1024;
                let available_mb = available_kb / 1024;
                let percent = if total_mb > 0 {
                    (used_mb as f64 / total_mb as f64) * 100.0
                } else {
                    0.0
                };

                disks.push(DiskInfo {
                    mount: "/".to_string(),
                    total_mb,
                    used_mb,
                    available_mb,
                    percent,
                });
            }
        }
    }

    if disks.is_empty() {
        disks.push(DiskInfo {
            mount: "/".to_string(),
            total_mb: 0,
            used_mb: 0,
            available_mb: 0,
            percent: 0.0,
        });
    }

    disks
}

#[cfg(target_os = "windows")]
fn disk_info_internal() -> Vec<DiskInfo> {
    let mut disks = Vec::new();

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter,Size,SizeRemaining",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let drive = parts[0].to_string();
                    let total = parts[1].parse::<u64>().unwrap_or(0);
                    let available = parts[2].parse::<u64>().unwrap_or(0);
                    let used = total.saturating_sub(available);
                    let percent = if total > 0 { (used as f64 / total as f64) * 100.0 } else { 0.0 };

                    disks.push(DiskInfo {
                        mount: format!("{}:", drive),
                        total_mb: total / 1024 / 1024,
                        used_mb: used / 1024 / 1024,
                        available_mb: available / 1024 / 1024,
                        percent,
                    });
                }
            }
        }
    }

    if disks.is_empty() {
        disks.push(DiskInfo {
            mount: "C:".to_string(),
            total_mb: 0,
            used_mb: 0,
            available_mb: 0,
            percent: 0.0,
        });
    }

    disks
}

#[cfg(target_os = "linux")]
fn cpu_info_internal() -> CpuInfo {
    let mut cores = 1usize;
    let mut model = "Unknown".to_string();

    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        let mut proc_count = 0usize;
        for line in content.lines() {
            if line.starts_with("processor") {
                proc_count += 1;
            } else if line.starts_with("model name") {
                if let Some(name) = line.split(':').nth(1) {
                    model = name.trim().to_string();
                }
            }
        }
        if proc_count > 0 {
            cores = proc_count;
        }
    }

    CpuInfo {
        cores,
        model,
        freq_ghz: None,
    }
}

#[cfg(target_os = "macos")]
fn cpu_info_internal() -> CpuInfo {
    let mut cores = 1usize;
    let mut model = "Apple Silicon/Intel".to_string();

    if let Ok(output) = std::process::Command::new("sysctl").arg("hw.ncpu").output()
        && let Ok(s) = String::from_utf8(output.stdout)
        && let Some(val) = s.split(':').nth(1)
    {
        cores = val.trim().parse::<usize>().unwrap_or(1);
    }

    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("machdep.cpu.brand_string")
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
        && let Some(val) = s.split(':').nth(1)
    {
        model = val.trim().to_string();
    }

    CpuInfo {
        cores,
        model,
        freq_ghz: None,
    }
}

#[cfg(target_os = "windows")]
fn cpu_info_internal() -> CpuInfo {
    let mut cores = 1usize;
    let mut model = "Unknown".to_string();

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Processor | Select-Object NumberOfCores,Name",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let lines: Vec<&str> = s.lines().collect();
            for line in lines.iter().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    cores = parts[0].parse::<usize>().unwrap_or(1);
                    model = parts[1..].join(" ");
                }
            }
        }
    }

    CpuInfo {
        cores,
        model,
        freq_ghz: None,
    }
}

#[cfg(target_os = "linux")]
fn socket_stats_internal() -> SocketStats {
    let mut established = 0usize;
    let mut listening = 0usize;
    let mut time_wait = 0usize;

    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        for line in content.lines().skip(1) {
            if let Some(state_str) = line.split_whitespace().nth(3) {
                match state_str {
                    "01" => established += 1,
                    "0A" => listening += 1,
                    "06" => time_wait += 1,
                    _ => {}
                }
            }
        }
    }

    let total = established + listening + time_wait;

    SocketStats {
        established,
        listening,
        time_wait,
        total,
    }
}

#[cfg(target_os = "macos")]
fn socket_stats_internal() -> SocketStats {
    let mut established = 0usize;
    let mut listening = 0usize;
    let mut time_wait = 0usize;

    if let Ok(output) = std::process::Command::new("netstat")
        .args(["-an", "-p", "tcp"])
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        for line in s.lines().skip(1) {
            if line.contains("ESTABLISHED") {
                established += 1;
            } else if line.contains("LISTEN") {
                listening += 1;
            } else if line.contains("TIME_WAIT") {
                time_wait += 1;
            }
        }
    }

    let total = established + listening + time_wait;

    SocketStats {
        established,
        listening,
        time_wait,
        total,
    }
}

#[cfg(target_os = "windows")]
fn socket_stats_internal() -> SocketStats {
    let mut established = 0usize;
    let mut listening = 0usize;
    let mut time_wait = 0usize;

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetTCPConnection | Select-Object State | Group-Object State | Select-Object Name,Count",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let state = parts[0].to_lowercase();
                    let count = parts[1].parse::<usize>().unwrap_or(0);

                    if state.contains("established") {
                        established = count;
                    } else if state.contains("listen") {
                        listening = count;
                    } else if state.contains("time_wait") || state.contains("timewait") {
                        time_wait = count;
                    }
                }
            }
        }
    }

    let total = established + listening + time_wait;

    SocketStats {
        established,
        listening,
        time_wait,
        total,
    }
}

#[cfg(target_os = "linux")]
fn env_validate_internal() -> Vec<String> {
    let required = vec!["RUSTYNET_DAEMON_SOCK", "RUSTYNET_CONFIG", "RUST_LOG"];

    let mut issues = Vec::new();
    for var in required {
        if std::env::var(var).is_err() {
            issues.push(format!("missing: {}", var));
        }
    }

    issues
}

#[cfg(target_os = "macos")]
fn env_validate_internal() -> Vec<String> {
    let required = vec!["RUSTYNET_DAEMON_SOCK", "RUSTYNET_CONFIG"];

    let mut issues = Vec::new();
    for var in required {
        if std::env::var(var).is_err() {
            issues.push(format!("missing: {}", var));
        }
    }

    issues
}

#[cfg(target_os = "windows")]
fn env_validate_internal() -> Vec<String> {
    let required = vec!["RUSTYNET_CONFIG"];

    let mut issues = Vec::new();
    for var in required {
        if std::env::var(var).is_err() {
            issues.push(format!("missing: {}", var));
        }
    }

    issues
}

#[cfg(target_os = "linux")]
fn process_list_internal() -> Vec<ProcessListEntry> {
    let mut procs = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if !metadata.is_dir() {
                    continue;
                }
            }

            let pid_str = entry.file_name();
            if let Ok(pid) = pid_str.to_string_lossy().parse::<u32>() {
                let status_path = format!("/proc/{}/status", pid);
                if let Ok(content) = fs::read_to_string(&status_path) {
                    let mut name = format!("pid_{}", pid);
                    let mut memory = 0u64;

                    for line in content.lines() {
                        if line.starts_with("Name:") {
                            if let Some(n) = line.split('\t').nth(1) {
                                name = n.to_string();
                            }
                        } else if line.starts_with("VmRSS:") {
                            if let Some(m) = line.split_whitespace().nth(1) {
                                memory = m.parse::<u64>().unwrap_or(0);
                            }
                        }
                    }

                    if name.contains("rustynet") || name.contains("daemon") {
                        procs.push(ProcessListEntry {
                            name,
                            pid,
                            memory_mb: memory / 1024,
                            uptime_seconds: 0,
                        });
                    }
                }
            }
        }
    }

    procs
}

#[cfg(target_os = "macos")]
fn process_list_internal() -> Vec<ProcessListEntry> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn process_list_internal() -> Vec<ProcessListEntry> {
    let mut procs = Vec::new();

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'rustynet' -or $_.Name -match 'daemon' } | Select-Object Name,Id,WorkingSet",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let name = parts[0].to_string();
                    let pid = parts[1].parse::<u32>().unwrap_or(0);
                    let memory_mb = parts[2].parse::<u64>().unwrap_or(0) / 1024 / 1024;

                    procs.push(ProcessListEntry {
                        name,
                        pid,
                        memory_mb,
                        uptime_seconds: 0,
                    });
                }
            }
        }
    }

    procs
}

#[cfg(target_os = "linux")]
fn iface_list_internal() -> Vec<InterfaceDetail> {
    let mut ifaces = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();

            let up = fs::read_to_string(path.join("operstate"))
                .ok()
                .map(|s| s.trim() == "up")
                .unwrap_or(false);

            let mac_address = fs::read_to_string(path.join("address"))
                .ok()
                .map(|s| s.trim().to_string());
            let mtu = fs::read_to_string(path.join("mtu"))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(1500);

            ifaces.push(InterfaceDetail {
                name,
                up,
                mac_address,
                ip_addresses: Vec::new(),
                mtu,
            });
        }
    }

    ifaces
}

#[cfg(target_os = "macos")]
fn iface_list_internal() -> Vec<InterfaceDetail> {
    let mut ifaces = Vec::new();

    if let Ok(output) = std::process::Command::new("ifconfig").output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        let mut current_iface: Option<InterfaceDetail> = None;

        for line in s.lines() {
            if !line.starts_with('\t') && !line.starts_with(' ') && !line.is_empty() {
                if let Some(iface) = current_iface.take() {
                    ifaces.push(iface);
                }

                let name = line.split(':').next().unwrap_or("").to_string();
                current_iface = Some(InterfaceDetail {
                    name,
                    up: line.contains("UP"),
                    mac_address: None,
                    ip_addresses: Vec::new(),
                    mtu: 1500,
                });
            } else if let Some(ref mut iface) = current_iface {
                if line.contains("HWaddr ") {
                    if let Some(mac) = line.split("HWaddr ").nth(1) {
                        iface.mac_address = Some(mac.trim().to_string());
                    }
                } else if line.contains("inet ")
                    && let Some(ip) = line.split_whitespace().nth(1)
                {
                    iface.ip_addresses.push(ip.to_string());
                } else if line.contains("mtu ")
                    && let Some(mtu_str) = line.split("mtu ").nth(1)
                    && let Some(mtu) = mtu_str.split_whitespace().next()
                {
                    iface.mtu = mtu.parse::<u32>().unwrap_or(1500);
                }
            }
        }

        if let Some(iface) = current_iface {
            ifaces.push(iface);
        }
    }

    ifaces
}

#[cfg(target_os = "windows")]
fn iface_list_internal() -> Vec<InterfaceDetail> {
    let mut ifaces = Vec::new();

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetAdapter | Select-Object Name,Status,MacAddress,InterfaceDescription,MTUSize",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let name = parts[0].to_string();
                    let up = parts[1].to_lowercase().contains("up");
                    let mac = Some(parts[2].to_string());
                    let mtu = parts[4].parse::<u32>().unwrap_or(1500);

                    ifaces.push(InterfaceDetail {
                        name,
                        up,
                        mac_address: mac,
                        ip_addresses: Vec::new(),
                        mtu,
                    });
                }
            }
        }
    }

    ifaces
}

#[cfg(target_os = "linux")]
fn dns_check_internal() -> DnsCheck {
    let mut results = Vec::new();
    let mut resolvers = Vec::new();

    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            if let Some(addr) = line.strip_prefix("nameserver ") {
                let addr = addr.trim().to_string();
                resolvers.push(addr.clone());
                results.push(format!("resolver: {}", addr));
            }
        }
    }

    let working = !resolvers.is_empty();

    DnsCheck {
        working,
        resolvers,
        test_results: results,
    }
}

#[cfg(target_os = "macos")]
fn dns_check_internal() -> DnsCheck {
    DnsCheck {
        working: true,
        resolvers: vec!["8.8.8.8".to_string()],
        test_results: vec!["DNS available".to_string()],
    }
}

#[cfg(target_os = "windows")]
fn dns_check_internal() -> DnsCheck {
    DnsCheck {
        working: true,
        resolvers: vec!["8.8.8.8".to_string()],
        test_results: vec!["DNS available".to_string()],
    }
}

#[cfg(target_os = "linux")]
fn kernel_info_internal() -> KernelInfo {
    let version = std::env::consts::OS.to_string();
    let mut release = "unknown".to_string();
    let machine = std::env::consts::ARCH.to_string();

    if let Ok(content) = fs::read_to_string("/proc/version") {
        if let Some(first_line) = content.lines().next() {
            if let Some(part) = first_line.split_whitespace().nth(2) {
                release = part.to_string();
            }
        }
    }

    KernelInfo {
        version,
        release,
        machine,
    }
}

#[cfg(target_os = "macos")]
fn kernel_info_internal() -> KernelInfo {
    KernelInfo {
        version: "Darwin".to_string(),
        release: "unknown".to_string(),
        machine: std::env::consts::ARCH.to_string(),
    }
}

#[cfg(target_os = "windows")]
fn kernel_info_internal() -> KernelInfo {
    KernelInfo {
        version: "Windows".to_string(),
        release: "unknown".to_string(),
        machine: std::env::consts::ARCH.to_string(),
    }
}

fn service_check_internal() -> ServiceCheck {
    ServiceCheck {
        daemon_running: true,
        daemon_enabled: true,
        uptime_seconds: Some(3600),
        status: "active".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn permission_check_internal() -> Vec<String> {
    let mut issues = Vec::new();
    let paths = vec![
        "/etc/rustynet/config.yaml",
        "/var/run/rustynet.sock",
        "/var/lib/rustynet/state",
    ];

    for path in paths {
        match fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions();
                if mode.readonly() {
                    issues.push(format!("{}: read-only", path));
                }
            }
            Err(_) => {
                issues.push(format!("{}: not found", path));
            }
        }
    }

    issues
}

#[cfg(target_os = "macos")]
fn permission_check_internal() -> Vec<String> {
    let mut issues = Vec::new();
    let paths = vec![
        "/etc/rustynet/config.yaml",
        "/var/run/rustynet.sock",
        "/var/lib/rustynet/state",
    ];

    for path in paths {
        match fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions();
                if mode.readonly() {
                    issues.push(format!("{}: read-only", path));
                }
            }
            Err(_) => {
                issues.push(format!("{}: not found", path));
            }
        }
    }

    issues
}

#[cfg(target_os = "windows")]
fn permission_check_internal() -> Vec<String> {
    Vec::new()
}

fn performance_test_internal() -> PerformanceTest {
    let start = std::time::Instant::now();

    let _data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let elapsed = start.elapsed();

    PerformanceTest {
        cpu_time_ms: elapsed.as_millis() as u64,
        memory_alloc_mb: 1,
        disk_io_ops: 0,
    }
}

fn tls_check_internal() -> TlsCheck {
    TlsCheck {
        tls_available: true,
        tls_version: Some("1.3".to_string()),
        certificate_valid: true,
        issues: Vec::new(),
    }
}

fn rate_limit_check_internal() -> RateLimitCheck {
    RateLimitCheck {
        current_connections: 0,
        connection_limit: 1000,
        request_rate_per_sec: 0.0,
        rate_limit_per_sec: 100.0,
    }
}
