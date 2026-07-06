use crate::config::MonitorConfig;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;

pub struct SpawnedOrchestrator {
    pub child: tokio::process::Child,
    pub job_id: String,
    pub report_dir: PathBuf,
    pub job_state_path: PathBuf,
}

pub fn build_loop_args(config: &MonitorConfig) -> Vec<String> {
    let mut normalized = config.clone();
    let _ = crate::config::normalize_linux_lab_vms(&mut normalized, &[]);
    normalized.apply_fast_stage_defaults();
    let config = &normalized;
    let area = if config.area.is_empty() {
        MonitorConfig::default().area
    } else {
        config.area.clone()
    };
    let mut args = vec!["start".to_string(), area.clone()];
    let wants_macos = config.wants_macos();
    let wants_windows = config.wants_windows();
    let rust_engine = config.engine.trim().eq_ignore_ascii_case("rust-node");

    if wants_macos {
        args.push("macos=true".to_string());
    }
    if wants_windows {
        args.push("windows=true".to_string());
    }
    if config.macos_promote_exit {
        args.push("macos_promote_exit=true".to_string());
    }
    push_pair(&mut args, "exit_vm", &config.exit_vm);
    push_pair(&mut args, "client_vm", &config.client_vm);
    push_pair(&mut args, "entry_vm", &config.entry_vm);
    if wants_macos {
        push_pair(&mut args, "macos_vm", &config.macos_vm);
    }
    if wants_windows {
        push_pair(&mut args, "windows_vm", &config.windows_vm);
    }
    push_pair(&mut args, "exit_platform", &config.exit_platform);
    push_pair(&mut args, "relay_platform", &config.relay_platform);
    push_pair(&mut args, "anchor_platform", &config.anchor_platform);
    push_pair(&mut args, "admin_platform", &config.admin_platform);
    push_pair(
        &mut args,
        "blind_exit_platform",
        &config.blind_exit_platform,
    );
    push_pair(&mut args, "rebuild_nodes", &config.rebuild_nodes);
    if config.skip_linux_live_suite {
        args.push("skip_linux_live_suite=true".to_string());
    }
    args.push("triage_on_failure=false".to_string());
    if config.dry_run {
        args.push("dry_run=true".to_string());
    }
    if rust_engine {
        args.push("rust_engine=true".to_string());
    } else {
        args.push("legacy_bash=true".to_string());
    }
    args
}

/// Build orchestrator args matching `build_orchestrator_args` in
/// `crates/rustynet-mcp/src/bin/deepseek.rs`.
#[allow(dead_code)]
pub fn build_orchestrator_args(
    config: &MonitorConfig,
    inventory: &str,
    ssh_identity: &str,
    known_hosts: &str,
    report_dir: &str,
) -> Vec<String> {
    let mut a: Vec<String> = vec!["ops".to_string(), "vm-lab-orchestrate-live-lab".to_string()];
    a.extend(["--inventory".to_string(), inventory.to_string()]);
    a.extend(["--ssh-identity-file".to_string(), ssh_identity.to_string()]);
    a.extend(["--known-hosts-file".to_string(), known_hosts.to_string()]);
    a.extend(["--report-dir".to_string(), report_dir.to_string()]);
    a.push("--trust-inventory-ready".to_string());
    a.push("--skip-gates".to_string());
    a.push("--skip-soak".to_string());
    a.push("--skip-cross-network".to_string());
    a.extend(["--source-mode".to_string(), "working-tree".to_string()]);

    if config.engine.trim().eq_ignore_ascii_case("rust-node") {
        for assignment in synthesize_rust_node_args(config) {
            a.extend(["--node".to_string(), assignment]);
        }
        if !config.rebuild_nodes.is_empty() {
            a.extend(["--rebuild-nodes".to_string(), config.rebuild_nodes.clone()]);
        }
    } else {
        if !config.macos_vm.is_empty() {
            a.extend(["--macos-vm".to_string(), config.macos_vm.clone()]);
        }
        if !config.windows_vm.is_empty() {
            a.extend(["--windows-vm".to_string(), config.windows_vm.clone()]);
        }
        if !config.exit_vm.is_empty() {
            a.extend(["--exit-vm".to_string(), config.exit_vm.clone()]);
        }
        if !config.client_vm.is_empty() {
            a.extend(["--client-vm".to_string(), config.client_vm.clone()]);
        }
        if !config.rebuild_nodes.is_empty() {
            a.extend(["--rebuild-nodes".to_string(), config.rebuild_nodes.clone()]);
        }

        if !config.exit_platform.is_empty() {
            a.extend(["--exit-platform".to_string(), config.exit_platform.clone()]);
        }
        if !config.relay_platform.is_empty() {
            a.extend([
                "--relay-platform".to_string(),
                config.relay_platform.clone(),
            ]);
        }
        if !config.anchor_platform.is_empty() {
            a.extend([
                "--anchor-platform".to_string(),
                config.anchor_platform.clone(),
            ]);
        }
        if !config.admin_platform.is_empty() {
            a.extend([
                "--admin-platform".to_string(),
                config.admin_platform.clone(),
            ]);
        }
        if !config.blind_exit_platform.is_empty() {
            a.extend([
                "--blind-exit-platform".to_string(),
                config.blind_exit_platform.clone(),
            ]);
        }
        if config.macos_promote_exit {
            a.push("--macos-promote-exit".to_string());
        }
        a.push("--legacy-bash-orchestrator".to_string());
    }

    let mut normalized = config.clone();
    normalized.apply_fast_stage_defaults();
    if normalized.skip_linux_live_suite {
        a.push("--skip-linux-live-suite".to_string());
    }
    if config.dry_run {
        a.push("--dry-run".to_string());
    }

    a
}

fn synthesize_rust_node_args(config: &MonitorConfig) -> Vec<String> {
    let mut out = Vec::new();
    let exit_platform = config.exit_platform.trim();
    let non_linux_exit = config.macos_promote_exit
        || matches!(exit_platform, "macos" | "windows");
    if !non_linux_exit && !config.exit_vm.is_empty() {
        out.push(format!("{}:exit", config.exit_vm));
    }
    if !config.client_vm.is_empty() {
        out.push(format!("{}:client", config.client_vm));
    }
    if !config.entry_vm.is_empty() {
        out.push(format!("{}:entry", config.entry_vm));
    }
    if config.wants_macos() && !config.macos_vm.is_empty() {
        out.push(format!(
            "{}:{}",
            config.macos_vm,
            rust_node_role_for_platform(config, "macos")
        ));
    }
    if config.wants_windows() && !config.windows_vm.is_empty() {
        out.push(format!(
            "{}:{}",
            config.windows_vm,
            rust_node_role_for_platform(config, "windows")
        ));
    }
    let mut seen = BTreeSet::new();
    out.retain(|arg| seen.insert(arg.clone()));
    out
}

fn rust_node_role_for_platform(config: &MonitorConfig, platform: &str) -> &'static str {
    let selected = |value: &str| value.eq_ignore_ascii_case(platform);
    if (config.macos_promote_exit && platform == "macos") || selected(&config.exit_platform) {
        "exit"
    } else if selected(&config.relay_platform) {
        "relay"
    } else if selected(&config.anchor_platform) || selected(&config.admin_platform) {
        "anchor"
    } else if selected(&config.blind_exit_platform) {
        "exit"
    } else {
        "client"
    }
}

/// Spawn the orchestrator subprocess with its own process group and durable monitor job state.
pub fn spawn_orchestrator(
    repo_root: &Path,
    config: &MonitorConfig,
    patch_model: &str,
    patch_variant: &str,
    review_model: &str,
    patch_iterations: u8,
    review_iterations: u8,
) -> Result<SpawnedOrchestrator> {
    let job_id = format!(
        "monitor-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    let report_dir = repo_root
        .join("state")
        .join(format!("monitor-loop-{job_id}"));
    std::fs::create_dir_all(&report_dir)
        .with_context(|| format!("creating {}", report_dir.display()))?;
    let job_dir = repo_root.join("state/lab-monitor-jobs");
    std::fs::create_dir_all(&job_dir).with_context(|| format!("creating {}", job_dir.display()))?;
    let job_state_path = job_dir.join(format!("{job_id}.json"));

    let args = build_loop_args(config);
    let binary = repo_root.join("scripts/loop/opencode_loop.sh");

    tracing::info!(?binary, ?args, "spawning opencode live-lab loop");

    let stdout_log =
        std::fs::File::create(report_dir.join("monitor_stdout.log")).with_context(|| {
            format!(
                "creating {}",
                report_dir.join("monitor_stdout.log").display()
            )
        })?;
    let stderr_log =
        std::fs::File::create(report_dir.join("monitor_stderr.log")).with_context(|| {
            format!(
                "creating {}",
                report_dir.join("monitor_stderr.log").display()
            )
        })?;

    let child = tokio::process::Command::new(&binary)
        .args(&args)
        .env("OPENCODE_LOOP_MAX_CYCLES", "0")
        .env("OPENCODE_MAIN_MODEL", patch_model)
        .env("OPENCODE_MAIN_VARIANT", patch_variant)
        .env("OPENCODE_REVIEW_MODEL", review_model)
        .env("OPENCODE_MAIN_ITERATIONS", patch_iterations.to_string())
        .env("OPENCODE_REVIEW_ITERATIONS", review_iterations.to_string())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .stdin(Stdio::null())
        .process_group(0)
        .spawn()
        .with_context(|| format!("spawning OpenCode loop at {}", binary.display()))?;

    write_job_state(
        &job_state_path,
        &job_id,
        "running",
        child.id(),
        config.area.as_str(),
        &report_dir,
    )?;

    Ok(SpawnedOrchestrator {
        child,
        job_id,
        report_dir,
        job_state_path,
    })
}

fn push_pair(args: &mut Vec<String>, key: &str, value: &str) {
    if !value.is_empty() {
        args.push(format!("{key}={value}"));
    }
}

pub fn write_job_state(
    path: &Path,
    job_id: &str,
    state: &str,
    pid: Option<u32>,
    area: &str,
    report_dir: &Path,
) -> Result<()> {
    let started_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let job = crate::data::job_watcher::JobState {
        job_id: job_id.to_owned(),
        state: state.to_owned(),
        pid,
        started_unix: Some(started_unix),
        area: area.to_owned(),
        report_dir: report_dir.display().to_string(),
        request_args: None,
    };
    let raw = serde_json::to_string_pretty(&job)?;
    std::fs::write(path, raw).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orchestrator_args_include_ops_prefix() {
        let args = build_orchestrator_args(
            &MonitorConfig::default(),
            "inventory.json",
            "id_ed25519",
            "known_hosts",
            "report",
        );

        assert_eq!(args[0], "ops");
        assert_eq!(args[1], "vm-lab-orchestrate-live-lab");
        assert!(args.iter().any(|arg| arg == "--node"));
        assert!(!args.iter().any(|arg| arg == "--exit-vm"));
        assert!(!args.iter().any(|arg| arg == "--legacy-bash-orchestrator"));
    }

    #[test]
    fn direct_orchestrator_args_legacy_engine_uses_legacy_flags() {
        let config = MonitorConfig {
            engine: "legacy-bash".to_owned(),
            ..MonitorConfig::default()
        };
        let args = build_orchestrator_args(
            &config,
            "inventory.json",
            "id_ed25519",
            "known_hosts",
            "report",
        );

        assert!(args.windows(2).any(|w| w == ["--exit-vm", "debian-headless-1"]));
        assert!(args.iter().any(|arg| arg == "--legacy-bash-orchestrator"));
        assert!(!args.iter().any(|arg| arg == "--node"));
    }

    #[test]
    fn loop_args_start_unlimited_opencode_loop_for_macos_exit() {
        let config = MonitorConfig {
            macos_promote_exit: true,
            skip_linux_live_suite: true,
            rebuild_nodes: "macos-utm-1".into(),
            ..MonitorConfig::default()
        };

        let args = build_loop_args(&config);

        assert_eq!(args[0], "start");
        assert_eq!(args[1], "macOS exit");
        assert!(args.iter().any(|arg| arg == "macos=true"));
        assert!(args.iter().any(|arg| arg == "macos_promote_exit=true"));
        assert!(args.iter().any(|arg| arg == "entry_vm=debian-headless-3"));
        assert!(args.iter().any(|arg| arg == "skip_linux_live_suite=true"));
        assert!(args.iter().any(|arg| arg == "triage_on_failure=false"));
        assert!(args.iter().any(|arg| arg == "rust_engine=true"));
        assert!(!args.iter().any(|arg| arg == "legacy_bash=true"));
    }

    #[test]
    fn rust_node_synthesis_promotes_macos_exit_without_duplicate_linux_exit() {
        let config = MonitorConfig {
            macos_promote_exit: true,
            ..MonitorConfig::default()
        };
        let assignments = synthesize_rust_node_args(&config);

        assert!(assignments.contains(&"macos-utm-1:exit".to_owned()));
        assert!(!assignments.contains(&"debian-headless-1:exit".to_owned()));
    }
}
