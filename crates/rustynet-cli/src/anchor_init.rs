#![forbid(unsafe_code)]

use std::path::PathBuf;

use rustynet_control::roles::{ANCHOR_CAPABILITIES, RoleCapability, role_capability_csv};
use rustynetd::daemon::DEFAULT_ANCHOR_BUNDLE_PULL_ADDR;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorInitConfig {
    pub node_id: String,
    pub advertise_output_path: PathBuf,
    pub relay_bind: String,
    pub bundle_pull_addr: String,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorInitPlan {
    pub steps: Vec<AnchorInitStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorInitStep {
    SetPrimaryAdmin,
    InstallRelayService {
        relay_bind: String,
    },
    AdvertiseAnchorCapabilities {
        node_id: String,
        output_path: PathBuf,
        capabilities: Vec<RoleCapability>,
    },
    EnableBundlePull {
        bind_addr: String,
    },
    RestartDaemon,
}

pub fn build_anchor_init_plan(config: &AnchorInitConfig) -> Result<AnchorInitPlan, String> {
    if config.node_id.trim().is_empty() {
        return Err("anchor init requires non-empty node_id".to_owned());
    }
    if !config.dry_run {
        return Err(
            "anchor init currently requires --dry-run; execute the printed steps explicitly"
                .to_owned(),
        );
    }
    let mut capabilities = Vec::with_capacity(ANCHOR_CAPABILITIES.len() + 2);
    capabilities.push(RoleCapability::Anchor);
    capabilities.push(RoleCapability::RelayHost);
    capabilities.extend(ANCHOR_CAPABILITIES);
    Ok(AnchorInitPlan {
        steps: vec![
            AnchorInitStep::SetPrimaryAdmin,
            AnchorInitStep::InstallRelayService {
                relay_bind: config.relay_bind.clone(),
            },
            AnchorInitStep::AdvertiseAnchorCapabilities {
                node_id: config.node_id.clone(),
                output_path: config.advertise_output_path.clone(),
                capabilities,
            },
            AnchorInitStep::EnableBundlePull {
                bind_addr: config.bundle_pull_addr.clone(),
            },
            AnchorInitStep::RestartDaemon,
        ],
    })
}

pub fn render_anchor_init_plan(plan: &AnchorInitPlan) -> String {
    let mut out = String::from("anchor init plan:\n");
    for (index, step) in plan.steps.iter().enumerate() {
        out.push_str(&format!("  {}. {}\n", index + 1, render_step(step)));
    }
    out
}

fn render_step(step: &AnchorInitStep) -> String {
    match step {
        AnchorInitStep::SetPrimaryAdmin => "run `rustynet role set admin`".to_owned(),
        AnchorInitStep::InstallRelayService { relay_bind } => {
            format!("install relay sibling service with RUSTYNET_RELAY_BIND={relay_bind}")
        }
        AnchorInitStep::AdvertiseAnchorCapabilities {
            node_id,
            output_path,
            capabilities,
        } => format!(
            "run `rustynet anchor advertise --node-id {node_id} --capabilities {} --output {}`",
            role_capability_csv(capabilities),
            output_path.display()
        ),
        AnchorInitStep::EnableBundlePull { bind_addr } => {
            format!("enable loopback bundle-pull listener at {bind_addr}")
        }
        AnchorInitStep::RestartDaemon => "restart rustynetd after signed update applies".to_owned(),
    }
}

impl Default for AnchorInitConfig {
    fn default() -> Self {
        Self {
            node_id: "daemon-local".to_owned(),
            advertise_output_path: PathBuf::from("artifacts/membership/anchor-advertise.update"),
            relay_bind: "127.0.0.1:4500".to_owned(),
            bundle_pull_addr: DEFAULT_ANCHOR_BUNDLE_PULL_ADDR.to_owned(),
            dry_run: true,
        }
    }
}
