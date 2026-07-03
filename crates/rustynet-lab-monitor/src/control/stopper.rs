use anyhow::{Context, Result};
use std::path::Path;

/// Send SIGTERM to a process group. The `pgid` should be the pid of the
/// orchestrator process (which is the process group leader when spawned with
/// `process_group(0)`).
pub fn stop_orchestrator(pgid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;
        killpg(Pid::from_raw(pgid as i32), Signal::SIGTERM)
            .with_context(|| format!("sending SIGTERM to process group {pgid}"))?;
        tracing::info!(pgid, "SIGTERM sent to orchestrator process group");
    }
    #[cfg(not(unix))]
    {
        let _ = pgid;
        anyhow::bail!("process group signalling not supported on this platform");
    }
    Ok(())
}

pub fn request_stop_after_current(repo_root: &Path) -> Result<()> {
    let path = stop_after_current_path(repo_root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, chrono_like_timestamp())
        .with_context(|| format!("writing {}", path.display()))
}

pub fn stop_after_current_requested(repo_root: &Path) -> bool {
    stop_after_current_path(repo_root).exists()
}

fn stop_after_current_path(repo_root: &Path) -> std::path::PathBuf {
    repo_root
        .join("state")
        .join("opencode-loop")
        .join("stop-after-current")
}

fn chrono_like_timestamp() -> String {
    format!("{:?}\n", std::time::SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_after_current_writes_dashboard_sentinel() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert!(!stop_after_current_requested(dir.path()));
        request_stop_after_current(dir.path()).expect("request drain");

        assert!(stop_after_current_requested(dir.path()));
        assert!(
            dir.path()
                .join("state/opencode-loop/stop-after-current")
                .exists()
        );
    }
}
