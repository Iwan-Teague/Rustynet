use std::fs;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use serde_json::json;

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::{VmGuestPlatform, write_orchestration_artifact};

pub fn collect_failure_diagnostics(
    ctx: &OrchestrationContext,
    collect_diagnostics: bool,
    collect_artifacts: bool,
) -> Result<(), String> {
    if !collect_diagnostics && !collect_artifacts {
        return Ok(());
    }
    let diagnostics_dir = ctx.report_dir.join("diagnostics/rust-native-failure");
    fs::create_dir_all(&diagnostics_dir).map_err(|err| {
        format!(
            "create Rust-native diagnostics directory '{}': {err}",
            diagnostics_dir.display()
        )
    })?;

    let mut aliases = ctx.adapters.keys().cloned().collect::<Vec<_>>();
    aliases.sort();
    let mut nodes = serde_json::Map::new();
    let artifacts_dir = diagnostics_dir.join("artifacts");
    if collect_artifacts {
        fs::create_dir_all(&artifacts_dir).map_err(|err| {
            format!(
                "create Rust-native artifact directory '{}': {err}",
                artifacts_dir.display()
            )
        })?;
    }
    for alias in aliases {
        let adapter = ctx
            .adapters
            .get(&alias)
            .ok_or_else(|| format!("diagnostics adapter disappeared for '{alias}'"))?;
        let daemon_reason = if collect_diagnostics {
            match adapter.collect_daemon_failure_reason() {
                Ok(reason) => reason.unwrap_or_else(|| "no daemon failure marker found".to_owned()),
                Err(err) => format!("daemon diagnostic unavailable: {err}"),
            }
        } else {
            "diagnostic collection disabled".to_owned()
        };
        let artifact_path = if collect_artifacts {
            let extension = if adapter.platform() == VmGuestPlatform::Windows {
                "zip"
            } else {
                "tar.gz"
            };
            let path = artifacts_dir.join(format!("{alias}.{extension}"));
            adapter
                .collect_artifacts(&path)
                .map_err(|err| format!("collect failure artifacts for '{alias}': {err}"))?;
            Some(path.display().to_string())
        } else {
            None
        };
        nodes.insert(
            alias,
            json!({
                "platform": format!("{:?}", adapter.platform()).to_lowercase(),
                "daemon_reason": daemon_reason,
                "artifact": artifact_path,
            }),
        );
    }
    let summary = json!({
        "schema_version": 1,
        "collected_before_cleanup": true,
        "nodes": nodes,
    });
    write_orchestration_artifact(
        diagnostics_dir.join("summary.json").as_path(),
        &(serde_json::to_string_pretty(&summary)
            .map_err(|err| format!("serialize Rust-native diagnostics: {err}"))?
            + "\n"),
    )
}

pub fn register_shutdown_handlers_with<F>(mut register: F) -> Result<Arc<AtomicBool>, String>
where
    F: FnMut(i32, Arc<AtomicBool>) -> Result<(), String>,
{
    let flag = Arc::new(AtomicBool::new(false));
    register(signal_hook::consts::SIGTERM, Arc::clone(&flag))?;
    register(signal_hook::consts::SIGINT, Arc::clone(&flag))?;
    Ok(flag)
}

pub fn register_shutdown_handlers() -> Result<Arc<AtomicBool>, String> {
    register_shutdown_handlers_with(|signal, flag| {
        signal_hook::flag::register(signal, flag)
            .map(|_| ())
            .map_err(|err| format!("register signal {signal} cleanup handler failed: {err}"))
    })
}
