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
