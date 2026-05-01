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

pub struct InterfaceInfo {
    pub exists: bool,
    pub is_up: bool,
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
        Ok(out) if out.status.success() => {
            if let Ok(stdout) = String::from_utf8(out.stdout) {
                let is_up = stdout.contains("UP") && !stdout.contains("DOWN");
                InterfaceInfo {
                    exists: true,
                    is_up,
                }
            } else {
                InterfaceInfo {
                    exists: false,
                    is_up: false,
                }
            }
        }
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
        Ok(out) if out.status.success() => {
            if let Ok(stdout) = String::from_utf8(out.stdout) {
                let exists = stdout.to_lowercase().contains(&interface.to_lowercase());
                InterfaceInfo {
                    exists,
                    is_up: exists,
                }
            } else {
                InterfaceInfo {
                    exists: false,
                    is_up: false,
                }
            }
        }
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

#[cfg(target_os = "macos")]
fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}
