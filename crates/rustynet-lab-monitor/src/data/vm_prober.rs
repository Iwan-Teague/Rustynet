use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct VmStatus {
    pub alias: String,
    pub ip: String,
    pub platform: String,
    pub ssh_ok: bool,
    pub git_commit: Option<String>,
}

/// Probe a single VM: TCP/22 + git rev-parse via SSH.
pub async fn probe_vm(
    alias: &str,
    ip: &str,
    _utm_name: &str,
    ssh_user: &str,
    src_dir: &str,
) -> VmStatus {
    let ssh_ok = tcp_probe(ip, 22).await;
    let platform = infer_platform(alias, ssh_user);
    let git_commit = if ssh_ok && !ip.is_empty() && !ssh_user.is_empty() && !src_dir.is_empty() {
        git_rev_parse(ip, ssh_user, src_dir, &platform).await
    } else {
        None
    };

    VmStatus {
        alias: alias.to_string(),
        ip: ip.to_string(),
        platform,
        ssh_ok,
        git_commit,
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

async fn git_rev_parse(host: &str, user: &str, src_dir: &str, platform: &str) -> Option<String> {
    let target = format!("{user}@{host}");
    let cmd = if platform == "windows" {
        format!(
            "if exist {src_dir}\\RUSTYNET_SOURCE_COMMIT (type {src_dir}\\RUSTYNET_SOURCE_COMMIT) else (cd /d {src_dir} && git rev-parse --short HEAD 2>NUL)"
        )
    } else {
        format!(
            "test -f {0}/RUSTYNET_SOURCE_COMMIT && cat {0}/RUSTYNET_SOURCE_COMMIT || git -C {0} rev-parse --short HEAD 2>/dev/null",
            shell_quote(src_dir)
        )
    };
    let identity = std::env::var("HOME")
        .ok()
        .map(|h| format!("{h}/.ssh/rustynet_lab_ed25519"));

    let mut command = tokio::process::Command::new("ssh");
    command.args([
        "-o",
        "ConnectTimeout=3",
        // ConnectTimeout only bounds the TCP+handshake phase -- a VM that
        // accepts the connection but then wedges (stuck disk I/O, hung
        // shell) can leave the remote command running forever with no
        // timeout of its own. ServerAlive* makes ssh itself notice a dead
        // session within ~6s; the outer tokio::time::timeout below is the
        // hard backstop for the case where the connection stays technically
        // alive but the remote command never returns. Without either, this
        // single VM probe can block the whole event loop's refresh_state()
        // indefinitely, freezing every panel (not just VM status) until it
        // resolves.
        "-o",
        "ServerAliveInterval=2",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "BatchMode=yes",
    ]);
    if let Some(identity) = identity.as_deref()
        && std::path::Path::new(identity).exists()
    {
        command.args(["-o", "IdentitiesOnly=yes", "-i", identity]);
    }
    let output = tokio::time::timeout(
        Duration::from_secs(8),
        command.arg(&target).arg(&cmd).output(),
    )
    .await;

    match output {
        Ok(Ok(out)) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        }
        _ => None,
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
