use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub area: String,
    pub exit_vm: String,
    pub client_vm: String,
    #[serde(default = "default_entry_vm")]
    pub entry_vm: String,
    pub macos_vm: String,
    pub windows_vm: String,
    pub relay_platform: String,
    pub anchor_platform: String,
    pub exit_platform: String,
    pub admin_platform: String,
    pub blind_exit_platform: String,
    #[serde(default)]
    pub macos_promote_exit: bool,
    #[serde(default)]
    pub skip_linux_live_suite: bool,
    pub rebuild_nodes: String,
    #[serde(default)]
    pub triage_on_failure: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub disabled_stages: Vec<String>,
    #[serde(default)]
    pub patch_model_idx: usize,
    #[serde(default)]
    pub patch_variant_idx: usize,
    #[serde(default)]
    pub review_model_idx: usize,
    #[serde(default)]
    pub patch_iterations: u8,
    #[serde(default)]
    pub review_iterations: u8,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            area: "macOS exit".into(),
            exit_vm: "debian-headless-1".into(),
            client_vm: "debian-headless-2".into(),
            entry_vm: default_entry_vm(),
            macos_vm: "macos-utm-1".into(),
            windows_vm: "windows-utm-1".into(),
            relay_platform: String::new(),
            anchor_platform: String::new(),
            exit_platform: String::new(),
            admin_platform: String::new(),
            blind_exit_platform: String::new(),
            macos_promote_exit: false,
            skip_linux_live_suite: false,
            rebuild_nodes: String::new(),
            triage_on_failure: false,
            dry_run: false,
            disabled_stages: Vec::new(),
            patch_model_idx: 0,
            patch_variant_idx: 0,
            review_model_idx: 0,
            patch_iterations: 1,
            review_iterations: 1,
        }
    }
}

fn default_entry_vm() -> String {
    "debian-headless-3".into()
}

impl MonitorConfig {
    pub fn load(repo_root: &Path) -> Result<Self> {
        let path = config_path(repo_root);
        if path.exists() {
            let s = std::fs::read_to_string(&path)
                .with_context(|| format!("reading config at {}", path.display()))?;
            toml::from_str(&s).with_context(|| "parsing monitor config")
        } else {
            Ok(Self::default())
        }
    }

    #[allow(dead_code)]
    pub fn save(&self, repo_root: &Path) -> Result<()> {
        let path = config_path(repo_root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(self).context("serializing config")?;
        std::fs::write(&path, s).with_context(|| format!("writing config to {}", path.display()))
    }

    pub fn apply_fast_stage_defaults(&mut self) {
        if self.platform_specific_target() {
            self.skip_linux_live_suite = true;
            if !self
                .disabled_stages
                .iter()
                .any(|stage| stage == "linux_live_suite")
            {
                self.disabled_stages.push("linux_live_suite".to_owned());
            }
            self.disabled_stages.sort();
            self.disabled_stages.dedup();
        }
    }

    pub fn wants_macos(&self) -> bool {
        let area = self.area.to_ascii_lowercase();
        area.contains("macos")
            || self.macos_promote_exit
            || self.exit_platform == "macos"
            || self.relay_platform == "macos"
            || self.anchor_platform == "macos"
            || self.admin_platform == "macos"
            || self.blind_exit_platform == "macos"
    }

    pub fn wants_windows(&self) -> bool {
        let area = self.area.to_ascii_lowercase();
        area.contains("windows")
            || self.exit_platform == "windows"
            || self.relay_platform == "windows"
            || self.anchor_platform == "windows"
            || self.admin_platform == "windows"
            || self.blind_exit_platform == "windows"
    }

    pub fn platform_specific_target(&self) -> bool {
        self.wants_macos() || self.wants_windows()
    }

    pub fn apply_request_args(
        &mut self,
        args: &std::collections::HashMap<String, serde_json::Value>,
    ) {
        for (key, value) in args {
            match key.as_str() {
                "area" => assign_string(&mut self.area, value),
                "exit_vm" => assign_string(&mut self.exit_vm, value),
                "client_vm" => assign_string(&mut self.client_vm, value),
                "entry_vm" => assign_string(&mut self.entry_vm, value),
                "macos_vm" => assign_string(&mut self.macos_vm, value),
                "windows_vm" => assign_string(&mut self.windows_vm, value),
                "relay_platform" => assign_string(&mut self.relay_platform, value),
                "anchor_platform" => assign_string(&mut self.anchor_platform, value),
                "exit_platform" => assign_string(&mut self.exit_platform, value),
                "admin_platform" => assign_string(&mut self.admin_platform, value),
                "blind_exit_platform" => assign_string(&mut self.blind_exit_platform, value),
                "rebuild_nodes" => assign_string(&mut self.rebuild_nodes, value),
                "macos_promote_exit" => assign_bool(&mut self.macos_promote_exit, value),
                "skip_linux_live_suite" => assign_bool(&mut self.skip_linux_live_suite, value),
                "triage_on_failure" => assign_bool(&mut self.triage_on_failure, value),
                "dry_run" => assign_bool(&mut self.dry_run, value),
                _ => {}
            }
        }
        self.apply_fast_stage_defaults();
    }
}

fn config_path(repo_root: &Path) -> PathBuf {
    repo_root.join("state").join("monitor-config.toml")
}

pub fn normalize_linux_lab_vms(config: &mut MonitorConfig, linux_aliases: &[String]) -> Result<()> {
    let candidates = linux_vm_candidates(linux_aliases);
    let mut used = HashSet::new();

    config.exit_vm = choose_linux_vm(&config.exit_vm, "debian-headless-1", &candidates, &used)
        .context("selecting exit_vm")?;
    used.insert(config.exit_vm.clone());

    let requested_client =
        if config.client_vm == config.entry_vm || config.client_vm == config.exit_vm {
            ""
        } else {
            config.client_vm.as_str()
        };
    config.client_vm = choose_linux_vm(requested_client, "debian-headless-2", &candidates, &used)
        .context("selecting client_vm")?;
    used.insert(config.client_vm.clone());

    config.entry_vm = choose_linux_vm(&config.entry_vm, "debian-headless-3", &candidates, &used)
        .context("selecting entry_vm")?;
    used.insert(config.entry_vm.clone());

    if used.len() < 3 {
        bail!(
            "live lab needs three distinct linux VMs; got exit_vm={}, client_vm={}, entry_vm={}",
            config.exit_vm,
            config.client_vm,
            config.entry_vm
        );
    }
    Ok(())
}

fn linux_vm_candidates(linux_aliases: &[String]) -> Vec<String> {
    let mut candidates = linux_aliases.to_vec();
    for alias in [
        "debian-headless-1",
        "debian-headless-2",
        "debian-headless-3",
        "debian-headless-4",
    ] {
        if !candidates.iter().any(|candidate| candidate == alias) {
            candidates.push(alias.to_owned());
        }
    }
    candidates
}

fn choose_linux_vm(
    current: &str,
    preferred: &str,
    candidates: &[String],
    used: &HashSet<String>,
) -> Option<String> {
    if !current.is_empty()
        && candidates.iter().any(|candidate| candidate == current)
        && !used.contains(current)
    {
        return Some(current.to_owned());
    }
    if !preferred.is_empty()
        && candidates.iter().any(|candidate| candidate == preferred)
        && !used.contains(preferred)
    {
        return Some(preferred.to_owned());
    }
    candidates
        .iter()
        .find(|candidate| !used.contains(candidate.as_str()))
        .cloned()
}

fn assign_string(target: &mut String, value: &serde_json::Value) {
    if let Some(value) = value.as_str() {
        *target = value.to_owned();
    }
}

fn assign_bool(target: &mut bool, value: &serde_json::Value) {
    if let Some(value) = value.as_bool() {
        *target = value;
    }
}
