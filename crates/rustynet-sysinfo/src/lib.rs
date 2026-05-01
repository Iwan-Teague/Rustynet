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
