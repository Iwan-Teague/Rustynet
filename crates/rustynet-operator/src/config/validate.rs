use crate::config::parse::ParsedConfig;
use crate::config::persist::ConfigError;
use crate::host::HostProfile;
use crate::launch::{ExitChain, ExitChainHops, LanMode, LaunchProfile, is_valid_node_id};
use crate::role::{self, NodeRole, RolePolicyState, RolePreset};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMode {
    LinuxWireguard,
    LinuxWireguardUserspaceShared,
    MacosWireguard,
    MacosWireguardUserspaceShared,
}

impl BackendMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxWireguard => "linux-wireguard",
            Self::LinuxWireguardUserspaceShared => "linux-wireguard-userspace-shared",
            Self::MacosWireguard => "macos-wireguard",
            Self::MacosWireguardUserspaceShared => "macos-wireguard-userspace-shared",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "linux-wireguard" => Some(Self::LinuxWireguard),
            "linux-wireguard-userspace-shared" => Some(Self::LinuxWireguardUserspaceShared),
            "macos-wireguard" => Some(Self::MacosWireguard),
            "macos-wireguard-userspace-shared" => Some(Self::MacosWireguardUserspaceShared),
            _ => None,
        }
    }

    fn valid_for_host(self, host: HostProfile) -> bool {
        match host {
            HostProfile::Linux => matches!(
                self,
                Self::LinuxWireguard | Self::LinuxWireguardUserspaceShared
            ),
            HostProfile::Macos => matches!(
                self,
                Self::MacosWireguard | Self::MacosWireguardUserspaceShared
            ),
            HostProfile::Windows | HostProfile::Unsupported => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorConfig {
    pub socket_path: PathBuf,
    pub state_path: PathBuf,
    pub trust_evidence_path: PathBuf,
    pub trust_verifier_key_path: PathBuf,
    pub trust_watermark_path: PathBuf,
    pub auto_tunnel_enforce: bool,
    pub auto_tunnel_bundle_path: PathBuf,
    pub auto_tunnel_verifier_key_path: PathBuf,
    pub auto_tunnel_watermark_path: PathBuf,
    pub auto_tunnel_max_age_secs: u64,
    pub traversal_bundle_path: PathBuf,
    pub traversal_verifier_key_path: PathBuf,
    pub traversal_watermark_path: PathBuf,
    pub traversal_max_age_secs: u64,
    pub wg_interface: String,
    pub wg_listen_port: u16,
    pub auto_port_forward_exit: bool,
    pub auto_port_forward_lease_secs: u64,
    pub wg_private_key_path: PathBuf,
    pub wg_encrypted_private_key_path: PathBuf,
    pub wg_key_passphrase_path: PathBuf,
    pub wg_key_passphrase_credential_blob_path: PathBuf,
    pub signing_key_passphrase_credential_blob_path: PathBuf,
    pub wg_key_passphrase_keychain_account: String,
    pub wg_public_key_path: PathBuf,
    pub egress_interface: String,
    pub membership_snapshot_path: PathBuf,
    pub membership_log_path: PathBuf,
    pub membership_watermark_path: PathBuf,
    pub membership_owner_signing_key_path: PathBuf,
    pub backend_mode: BackendMode,
    pub dataplane_mode: String,
    pub privileged_helper_socket_path: PathBuf,
    pub privileged_helper_timeout_ms: u64,
    pub reconcile_interval_ms: u64,
    pub max_reconcile_failures: u64,
    pub fail_closed_ssh_allow: bool,
    pub fail_closed_ssh_cidrs: Vec<String>,
    pub trust_signer_key_path: PathBuf,
    pub auto_refresh_trust: bool,
    pub device_node_id: String,
    pub setup_complete: bool,
    pub node_role: NodeRole,
    pub setup_role_preset: Option<RolePreset>,
    pub manual_peer_override: bool,
    pub manual_peer_audit_log: PathBuf,
    pub default_launch_profile: LaunchProfile,
    pub auto_launch_on_start: bool,
    pub auto_launch_exit_node_id: Option<String>,
    pub auto_launch_lan_mode: LanMode,
    pub exit_chain: ExitChain,
    pub host_profile: HostProfile,
}

impl OperatorConfig {
    pub fn defaults_for_host(host: HostProfile, device_node_id: String) -> Self {
        let backend_mode = match host {
            HostProfile::Macos => BackendMode::MacosWireguard,
            HostProfile::Linux | HostProfile::Windows | HostProfile::Unsupported => {
                BackendMode::LinuxWireguard
            }
        };
        Self {
            socket_path: "/run/rustynet/rustynetd.sock".into(),
            state_path: "/var/lib/rustynet/rustynetd.state".into(),
            trust_evidence_path: "/var/lib/rustynet/rustynetd.trust".into(),
            trust_verifier_key_path: "/etc/rustynet/trust-evidence.pub".into(),
            trust_watermark_path: "/var/lib/rustynet/rustynetd.trust.watermark".into(),
            auto_tunnel_enforce: false,
            auto_tunnel_bundle_path: "/var/lib/rustynet/rustynetd.assignment".into(),
            auto_tunnel_verifier_key_path: "/etc/rustynet/assignment.pub".into(),
            auto_tunnel_watermark_path: "/var/lib/rustynet/rustynetd.assignment.watermark".into(),
            auto_tunnel_max_age_secs: 300,
            traversal_bundle_path: "/var/lib/rustynet/rustynetd.traversal".into(),
            traversal_verifier_key_path: "/etc/rustynet/traversal.pub".into(),
            traversal_watermark_path: "/var/lib/rustynet/rustynetd.traversal.watermark".into(),
            traversal_max_age_secs: 120,
            wg_interface: "rustynet0".to_owned(),
            wg_listen_port: 51820,
            auto_port_forward_exit: false,
            auto_port_forward_lease_secs: 1200,
            wg_private_key_path: "/run/rustynet/wireguard.key".into(),
            wg_encrypted_private_key_path: "/var/lib/rustynet/keys/wireguard.key.enc".into(),
            wg_key_passphrase_path: "/var/lib/rustynet/keys/wireguard.passphrase".into(),
            wg_key_passphrase_credential_blob_path:
                "/etc/rustynet/credentials/wg_key_passphrase.cred".into(),
            signing_key_passphrase_credential_blob_path:
                "/etc/rustynet/credentials/signing_key_passphrase.cred".into(),
            wg_key_passphrase_keychain_account: String::new(),
            wg_public_key_path: "/var/lib/rustynet/keys/wireguard.pub".into(),
            egress_interface: String::new(),
            membership_snapshot_path: "/var/lib/rustynet/membership.snapshot".into(),
            membership_log_path: "/var/lib/rustynet/membership.log".into(),
            membership_watermark_path: "/var/lib/rustynet/membership.watermark".into(),
            membership_owner_signing_key_path: "/etc/rustynet/membership.owner.key".into(),
            backend_mode,
            dataplane_mode: "hybrid-native".to_owned(),
            privileged_helper_socket_path: "/run/rustynet/rustynetd-privileged.sock".into(),
            privileged_helper_timeout_ms: 2000,
            reconcile_interval_ms: 1000,
            max_reconcile_failures: 5,
            fail_closed_ssh_allow: false,
            fail_closed_ssh_cidrs: Vec::new(),
            trust_signer_key_path: "/etc/rustynet/trust-evidence.key".into(),
            auto_refresh_trust: false,
            device_node_id,
            setup_complete: false,
            node_role: NodeRole::Client,
            setup_role_preset: None,
            manual_peer_override: false,
            manual_peer_audit_log: "/var/log/rustynet/manual-peer-override.log".into(),
            default_launch_profile: LaunchProfile::Menu,
            auto_launch_on_start: false,
            auto_launch_exit_node_id: None,
            auto_launch_lan_mode: LanMode::Skip,
            exit_chain: ExitChain {
                hops: ExitChainHops::One,
                entry: None,
                final_node: None,
            },
            host_profile: host,
        }
    }
}

fn validation_err(message: impl Into<String>) -> ConfigError {
    ConfigError::Validation(message.into())
}

fn bool_lenient(value: &str) -> bool {
    value == "1"
}

fn bool_strict(key: &str, value: &str) -> Result<bool, ConfigError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        other => Err(validation_err(format!(
            "Invalid persisted {key}='{other}'. Expected 0 or 1."
        ))),
    }
}

fn u16_field(key: &str, value: &str) -> Result<u16, ConfigError> {
    value.parse::<u16>().map_err(|_| {
        validation_err(format!(
            "Invalid persisted {key}='{value}'. Expected an integer."
        ))
    })
}

fn u64_field(key: &str, value: &str) -> Result<u64, ConfigError> {
    value.parse::<u64>().map_err(|_| {
        validation_err(format!(
            "Invalid persisted {key}='{value}'. Expected an integer."
        ))
    })
}

fn parse_cidrs(value: &str) -> Vec<String> {
    value
        .split(|ch: char| ch.is_whitespace() || ch == ',')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn build_and_enforce(
    parsed: &ParsedConfig,
    host: HostProfile,
    device_node_id: String,
    trust_signer_key_present: bool,
) -> Result<(OperatorConfig, Vec<String>), ConfigError> {
    let mut warnings = Vec::new();
    let mut cfg = OperatorConfig::defaults_for_host(host, device_node_id);
    let mut raw_node_role: Option<String> = None;
    let mut raw_preset: Option<String> = None;

    for (key, value) in &parsed.values {
        match key.as_str() {
            "SOCKET_PATH" => cfg.socket_path = value.into(),
            "STATE_PATH" => cfg.state_path = value.into(),
            "TRUST_EVIDENCE_PATH" => cfg.trust_evidence_path = value.into(),
            "TRUST_VERIFIER_KEY_PATH" => cfg.trust_verifier_key_path = value.into(),
            "TRUST_WATERMARK_PATH" => cfg.trust_watermark_path = value.into(),
            "AUTO_TUNNEL_ENFORCE" => cfg.auto_tunnel_enforce = bool_lenient(value),
            "AUTO_TUNNEL_BUNDLE_PATH" => cfg.auto_tunnel_bundle_path = value.into(),
            "AUTO_TUNNEL_VERIFIER_KEY_PATH" => cfg.auto_tunnel_verifier_key_path = value.into(),
            "AUTO_TUNNEL_WATERMARK_PATH" => cfg.auto_tunnel_watermark_path = value.into(),
            "AUTO_TUNNEL_MAX_AGE_SECS" => cfg.auto_tunnel_max_age_secs = u64_field(key, value)?,
            "TRAVERSAL_BUNDLE_PATH" => cfg.traversal_bundle_path = value.into(),
            "TRAVERSAL_VERIFIER_KEY_PATH" => cfg.traversal_verifier_key_path = value.into(),
            "TRAVERSAL_WATERMARK_PATH" => cfg.traversal_watermark_path = value.into(),
            "TRAVERSAL_MAX_AGE_SECS" => cfg.traversal_max_age_secs = u64_field(key, value)?,
            "WG_INTERFACE" => cfg.wg_interface = value.clone(),
            "WG_LISTEN_PORT" => cfg.wg_listen_port = u16_field(key, value)?,
            "AUTO_PORT_FORWARD_EXIT" => cfg.auto_port_forward_exit = bool_lenient(value),
            "AUTO_PORT_FORWARD_LEASE_SECS" => {
                cfg.auto_port_forward_lease_secs = u64_field(key, value)?
            }
            "WG_PRIVATE_KEY_PATH" => cfg.wg_private_key_path = value.into(),
            "WG_ENCRYPTED_PRIVATE_KEY_PATH" => cfg.wg_encrypted_private_key_path = value.into(),
            "WG_KEY_PASSPHRASE_PATH" => cfg.wg_key_passphrase_path = value.into(),
            "WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH" => {
                cfg.wg_key_passphrase_credential_blob_path = value.into();
            }
            "SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH" => {
                cfg.signing_key_passphrase_credential_blob_path = value.into();
            }
            "WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT" => {
                cfg.wg_key_passphrase_keychain_account = value.clone();
            }
            "WG_PUBLIC_KEY_PATH" => cfg.wg_public_key_path = value.into(),
            "EGRESS_INTERFACE" => cfg.egress_interface = value.clone(),
            "MEMBERSHIP_SNAPSHOT_PATH" => cfg.membership_snapshot_path = value.into(),
            "MEMBERSHIP_LOG_PATH" => cfg.membership_log_path = value.into(),
            "MEMBERSHIP_WATERMARK_PATH" => cfg.membership_watermark_path = value.into(),
            "MEMBERSHIP_OWNER_SIGNING_KEY_PATH" => {
                cfg.membership_owner_signing_key_path = value.into();
            }
            "BACKEND_MODE" => {
                cfg.backend_mode = BackendMode::parse(value).ok_or_else(|| {
                    validation_err(format!("Invalid persisted BACKEND_MODE='{value}'."))
                })?;
            }
            "DATAPLANE_MODE" => cfg.dataplane_mode = value.clone(),
            "PRIVILEGED_HELPER_SOCKET_PATH" => cfg.privileged_helper_socket_path = value.into(),
            "PRIVILEGED_HELPER_TIMEOUT_MS" => {
                cfg.privileged_helper_timeout_ms = u64_field(key, value)?
            }
            "RECONCILE_INTERVAL_MS" => cfg.reconcile_interval_ms = u64_field(key, value)?,
            "MAX_RECONCILE_FAILURES" => cfg.max_reconcile_failures = u64_field(key, value)?,
            "FAIL_CLOSED_SSH_ALLOW" => cfg.fail_closed_ssh_allow = bool_lenient(value),
            "FAIL_CLOSED_SSH_ALLOW_CIDRS" => cfg.fail_closed_ssh_cidrs = parse_cidrs(value),
            "TRUST_SIGNER_KEY_PATH" => cfg.trust_signer_key_path = value.into(),
            "AUTO_REFRESH_TRUST" => cfg.auto_refresh_trust = bool_lenient(value),
            "DEVICE_NODE_ID" => {
                if !value.is_empty() {
                    cfg.device_node_id = value.clone();
                }
            }
            "SETUP_COMPLETE" => cfg.setup_complete = bool_lenient(value),
            "NODE_ROLE" => raw_node_role = Some(value.clone()),
            "SETUP_ROLE_PRESET" => raw_preset = Some(value.clone()),
            "MANUAL_PEER_OVERRIDE" => {
                if value != "0" {
                    return Err(validation_err(format!(
                        "Invalid persisted MANUAL_PEER_OVERRIDE='{value}'. Manual peer break-glass is removed. Set MANUAL_PEER_OVERRIDE=0."
                    )));
                }
                cfg.manual_peer_override = false;
            }
            "MANUAL_PEER_AUDIT_LOG" => cfg.manual_peer_audit_log = value.into(),
            "DEFAULT_LAUNCH_PROFILE" => {
                cfg.default_launch_profile = LaunchProfile::parse(value).ok_or_else(|| {
                    validation_err(format!(
                        "Invalid persisted DEFAULT_LAUNCH_PROFILE='{value}'."
                    ))
                })?;
            }
            "AUTO_LAUNCH_ON_START" => cfg.auto_launch_on_start = bool_strict(key, value)?,
            "AUTO_LAUNCH_EXIT_NODE_ID" => {
                cfg.auto_launch_exit_node_id = if value.is_empty() {
                    None
                } else {
                    Some(value.clone())
                };
            }
            "AUTO_LAUNCH_LAN_MODE" => {
                cfg.auto_launch_lan_mode = LanMode::parse(value).ok_or_else(|| {
                    validation_err(format!(
                        "Invalid persisted AUTO_LAUNCH_LAN_MODE='{value}'. Allowed values: skip, on, off."
                    ))
                })?;
            }
            "EXIT_CHAIN_HOPS" => {
                cfg.exit_chain.hops = ExitChainHops::parse(value).ok_or_else(|| {
                    validation_err(format!(
                        "Invalid persisted EXIT_CHAIN_HOPS='{value}'. Allowed values: 1 or 2."
                    ))
                })?;
            }
            "EXIT_CHAIN_ENTRY_NODE_ID" => {
                cfg.exit_chain.entry = if value.is_empty() {
                    None
                } else {
                    Some(value.clone())
                };
            }
            "EXIT_CHAIN_FINAL_NODE_ID" => {
                cfg.exit_chain.final_node = if value.is_empty() {
                    None
                } else {
                    Some(value.clone())
                };
            }
            "HOST_PROFILE" => {}
            other => return Err(validation_err(format!("Unhandled config key '{other}'."))),
        }
    }

    if let Some(id) = &cfg.exit_chain.entry
        && !is_valid_node_id(id)
    {
        return Err(validation_err(format!(
            "Invalid persisted EXIT_CHAIN_ENTRY_NODE_ID='{id}'."
        )));
    }
    if let Some(id) = &cfg.exit_chain.final_node
        && !is_valid_node_id(id)
    {
        return Err(validation_err(format!(
            "Invalid persisted EXIT_CHAIN_FINAL_NODE_ID='{id}'."
        )));
    }
    if let Some(role) = raw_node_role.as_deref()
        && !role.is_empty()
    {
        let parsed_role = NodeRole::parse(role).ok_or_else(|| {
            validation_err(format!(
                "Invalid persisted NODE_ROLE='{role}'. Set NODE_ROLE to admin, client, or blind_exit."
            ))
        })?;
        if parsed_role == NodeRole::BlindExit && !role::is_blind_exit_supported_host(host) {
            return Err(validation_err(
                "Invalid persisted NODE_ROLE='blind_exit' on unsupported host. Set NODE_ROLE=client on this host."
                    .to_owned(),
            ));
        }
    }

    let (node_role, setup_role_preset, role_warnings) = role::normalize_role(
        raw_node_role.as_deref(),
        raw_preset.as_deref(),
        cfg.setup_complete,
        host,
    );
    warnings.extend(role_warnings);
    cfg.node_role = node_role;
    cfg.setup_role_preset = setup_role_preset;

    warnings.extend(sync_role_policy(&mut cfg, trust_signer_key_present));
    let (exit_chain, chain_warnings) = cfg
        .exit_chain
        .clone()
        .sanitize(cfg.node_role == NodeRole::BlindExit);
    cfg.exit_chain = exit_chain;
    warnings.extend(chain_warnings);

    if !cfg.backend_mode.valid_for_host(host) {
        return Err(validation_err(format!(
            "Invalid backend '{}' for host profile {:?}.",
            cfg.backend_mode.as_str(),
            host
        )));
    }
    if !cfg.auto_tunnel_enforce {
        warnings.push(
            "Unsigned/manual tunnel assignment is not allowed by default; forcing AUTO_TUNNEL_ENFORCE=1."
                .to_owned(),
        );
        cfg.auto_tunnel_enforce = true;
    }
    if cfg.fail_closed_ssh_allow {
        if cfg.fail_closed_ssh_cidrs.is_empty() {
            return Err(validation_err(
                "FAIL_CLOSED_SSH_ALLOW_CIDRS is required when FAIL_CLOSED_SSH_ALLOW=1.".to_owned(),
            ));
        }
    } else {
        cfg.fail_closed_ssh_cidrs.clear();
    }
    if cfg.wg_listen_port == 0 {
        return Err(validation_err(
            "Invalid WG_LISTEN_PORT '0'. Expected numeric range 1..65535.".to_owned(),
        ));
    }
    if cfg.auto_port_forward_lease_secs < 60 {
        return Err(validation_err(format!(
            "Invalid AUTO_PORT_FORWARD_LEASE_SECS '{}'. Expected numeric value >= 60.",
            cfg.auto_port_forward_lease_secs
        )));
    }
    if cfg.auto_port_forward_exit && host != HostProfile::Linux {
        warnings.push(
            "Auto port-forward is currently supported only on Linux. Forcing AUTO_PORT_FORWARD_EXIT=0."
                .to_owned(),
        );
        cfg.auto_port_forward_exit = false;
    }
    if cfg.auto_port_forward_exit && !matches!(cfg.node_role, NodeRole::Admin | NodeRole::BlindExit)
    {
        warnings.push(format!(
            "Auto port-forward applies only to exit-serving roles. Forcing AUTO_PORT_FORWARD_EXIT=0 for role '{}'.",
            cfg.node_role.as_str()
        ));
        cfg.auto_port_forward_exit = false;
    }

    Ok((cfg, warnings))
}

fn sync_role_policy(cfg: &mut OperatorConfig, trust_signer_key_present: bool) -> Vec<String> {
    let mut state = RolePolicyState {
        node_role: cfg.node_role,
        manual_peer_override: cfg.manual_peer_override,
        auto_refresh_trust: cfg.auto_refresh_trust,
        default_launch_profile: cfg.default_launch_profile,
        auto_port_forward_exit: cfg.auto_port_forward_exit,
        exit_chain: cfg.exit_chain.clone(),
        auto_launch_on_start: cfg.auto_launch_on_start,
        auto_launch_exit_node_id: cfg.auto_launch_exit_node_id.clone(),
        auto_launch_lan_mode: cfg.auto_launch_lan_mode,
        fail_closed_ssh_allow: cfg.fail_closed_ssh_allow,
        fail_closed_ssh_cidrs: cfg.fail_closed_ssh_cidrs.clone(),
    };
    let warnings = role::enforce_role_policy_defaults(
        &mut state,
        trust_signer_key_present,
        &cfg.trust_signer_key_path.to_string_lossy(),
    );
    cfg.node_role = state.node_role;
    cfg.manual_peer_override = state.manual_peer_override;
    cfg.auto_refresh_trust = state.auto_refresh_trust;
    cfg.default_launch_profile = state.default_launch_profile;
    cfg.auto_port_forward_exit = state.auto_port_forward_exit;
    cfg.exit_chain = state.exit_chain;
    cfg.auto_launch_on_start = state.auto_launch_on_start;
    cfg.auto_launch_exit_node_id = state.auto_launch_exit_node_id;
    cfg.auto_launch_lan_mode = state.auto_launch_lan_mode;
    cfg.fail_closed_ssh_allow = state.fail_closed_ssh_allow;
    cfg.fail_closed_ssh_cidrs = state.fail_closed_ssh_cidrs;
    warnings
}

pub fn to_wizard_env(cfg: &OperatorConfig) -> String {
    fn bool_token(value: bool) -> &'static str {
        if value { "1" } else { "0" }
    }

    let mut out = String::new();
    append_line(&mut out, "SOCKET_PATH", &cfg.socket_path.to_string_lossy());
    append_line(&mut out, "STATE_PATH", &cfg.state_path.to_string_lossy());
    append_line(
        &mut out,
        "TRUST_EVIDENCE_PATH",
        &cfg.trust_evidence_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "TRUST_VERIFIER_KEY_PATH",
        &cfg.trust_verifier_key_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "TRUST_WATERMARK_PATH",
        &cfg.trust_watermark_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "AUTO_TUNNEL_ENFORCE",
        bool_token(cfg.auto_tunnel_enforce),
    );
    append_line(
        &mut out,
        "AUTO_TUNNEL_BUNDLE_PATH",
        &cfg.auto_tunnel_bundle_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "AUTO_TUNNEL_VERIFIER_KEY_PATH",
        &cfg.auto_tunnel_verifier_key_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "AUTO_TUNNEL_WATERMARK_PATH",
        &cfg.auto_tunnel_watermark_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "AUTO_TUNNEL_MAX_AGE_SECS",
        &cfg.auto_tunnel_max_age_secs.to_string(),
    );
    append_line(
        &mut out,
        "TRAVERSAL_BUNDLE_PATH",
        &cfg.traversal_bundle_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "TRAVERSAL_VERIFIER_KEY_PATH",
        &cfg.traversal_verifier_key_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "TRAVERSAL_WATERMARK_PATH",
        &cfg.traversal_watermark_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "TRAVERSAL_MAX_AGE_SECS",
        &cfg.traversal_max_age_secs.to_string(),
    );
    append_line(&mut out, "WG_INTERFACE", &cfg.wg_interface);
    append_line(&mut out, "WG_LISTEN_PORT", &cfg.wg_listen_port.to_string());
    append_line(
        &mut out,
        "AUTO_PORT_FORWARD_EXIT",
        bool_token(cfg.auto_port_forward_exit),
    );
    append_line(
        &mut out,
        "AUTO_PORT_FORWARD_LEASE_SECS",
        &cfg.auto_port_forward_lease_secs.to_string(),
    );
    append_line(
        &mut out,
        "WG_PRIVATE_KEY_PATH",
        &cfg.wg_private_key_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "WG_ENCRYPTED_PRIVATE_KEY_PATH",
        &cfg.wg_encrypted_private_key_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "WG_KEY_PASSPHRASE_PATH",
        &cfg.wg_key_passphrase_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH",
        &cfg.wg_key_passphrase_credential_blob_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH",
        &cfg.signing_key_passphrase_credential_blob_path
            .to_string_lossy(),
    );
    append_line(
        &mut out,
        "WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT",
        &cfg.wg_key_passphrase_keychain_account,
    );
    append_line(
        &mut out,
        "WG_PUBLIC_KEY_PATH",
        &cfg.wg_public_key_path.to_string_lossy(),
    );
    append_line(&mut out, "EGRESS_INTERFACE", &cfg.egress_interface);
    append_line(
        &mut out,
        "MEMBERSHIP_SNAPSHOT_PATH",
        &cfg.membership_snapshot_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "MEMBERSHIP_LOG_PATH",
        &cfg.membership_log_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "MEMBERSHIP_WATERMARK_PATH",
        &cfg.membership_watermark_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "MEMBERSHIP_OWNER_SIGNING_KEY_PATH",
        &cfg.membership_owner_signing_key_path.to_string_lossy(),
    );
    append_line(&mut out, "BACKEND_MODE", cfg.backend_mode.as_str());
    append_line(&mut out, "DATAPLANE_MODE", &cfg.dataplane_mode);
    append_line(
        &mut out,
        "PRIVILEGED_HELPER_SOCKET_PATH",
        &cfg.privileged_helper_socket_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "PRIVILEGED_HELPER_TIMEOUT_MS",
        &cfg.privileged_helper_timeout_ms.to_string(),
    );
    append_line(
        &mut out,
        "RECONCILE_INTERVAL_MS",
        &cfg.reconcile_interval_ms.to_string(),
    );
    append_line(
        &mut out,
        "MAX_RECONCILE_FAILURES",
        &cfg.max_reconcile_failures.to_string(),
    );
    append_line(
        &mut out,
        "FAIL_CLOSED_SSH_ALLOW",
        bool_token(cfg.fail_closed_ssh_allow),
    );
    append_line(
        &mut out,
        "FAIL_CLOSED_SSH_ALLOW_CIDRS",
        &cfg.fail_closed_ssh_cidrs.join(" "),
    );
    append_line(
        &mut out,
        "TRUST_SIGNER_KEY_PATH",
        &cfg.trust_signer_key_path.to_string_lossy(),
    );
    append_line(
        &mut out,
        "AUTO_REFRESH_TRUST",
        bool_token(cfg.auto_refresh_trust),
    );
    append_line(&mut out, "DEVICE_NODE_ID", &cfg.device_node_id);
    append_line(&mut out, "HOST_PROFILE", cfg.host_profile.as_str());
    append_line(&mut out, "SETUP_COMPLETE", bool_token(cfg.setup_complete));
    append_line(&mut out, "NODE_ROLE", cfg.node_role.as_str());
    append_line(
        &mut out,
        "MANUAL_PEER_OVERRIDE",
        bool_token(cfg.manual_peer_override),
    );
    append_line(
        &mut out,
        "MANUAL_PEER_AUDIT_LOG",
        &cfg.manual_peer_audit_log.to_string_lossy(),
    );
    append_line(
        &mut out,
        "DEFAULT_LAUNCH_PROFILE",
        cfg.default_launch_profile.as_str(),
    );
    append_line(
        &mut out,
        "AUTO_LAUNCH_ON_START",
        bool_token(cfg.auto_launch_on_start),
    );
    append_line(
        &mut out,
        "AUTO_LAUNCH_EXIT_NODE_ID",
        cfg.auto_launch_exit_node_id.as_deref().unwrap_or(""),
    );
    append_line(
        &mut out,
        "AUTO_LAUNCH_LAN_MODE",
        cfg.auto_launch_lan_mode.as_str(),
    );
    append_line(&mut out, "EXIT_CHAIN_HOPS", cfg.exit_chain.hops.as_str());
    append_line(
        &mut out,
        "EXIT_CHAIN_ENTRY_NODE_ID",
        cfg.exit_chain.entry.as_deref().unwrap_or(""),
    );
    append_line(
        &mut out,
        "EXIT_CHAIN_FINAL_NODE_ID",
        cfg.exit_chain.final_node.as_deref().unwrap_or(""),
    );
    out
}

fn append_line(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push('=');
    out.push_str(value);
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse::parse_wizard_env;

    fn build(text: &str, host: HostProfile) -> Result<(OperatorConfig, Vec<String>), ConfigError> {
        let parsed = parse_wizard_env(text);
        build_and_enforce(&parsed, host, "test-node".to_owned(), true)
    }

    #[test]
    fn defaults_only_yields_valid_config() {
        let (cfg, _) = build("", HostProfile::Linux).unwrap();
        assert_eq!(cfg.node_role, NodeRole::Client);
        assert!(cfg.auto_tunnel_enforce);
        assert_eq!(cfg.wg_listen_port, 51820);
    }

    #[test]
    fn invalid_node_role_is_hard_error() {
        let result = build("NODE_ROLE=wizard\n", HostProfile::Linux);
        assert!(matches!(result, Err(ConfigError::Validation(_))));
    }

    #[test]
    fn persisted_blind_exit_on_windows_is_rejected() {
        let result = build("NODE_ROLE=blind_exit\n", HostProfile::Windows);
        assert!(matches!(result, Err(ConfigError::Validation(_))));
    }

    #[test]
    fn manual_peer_override_must_be_zero() {
        assert!(build("MANUAL_PEER_OVERRIDE=1\n", HostProfile::Linux).is_err());
        assert!(build("MANUAL_PEER_OVERRIDE=0\n", HostProfile::Linux).is_ok());
    }

    #[test]
    fn fail_closed_ssh_requires_cidrs() {
        assert!(build("FAIL_CLOSED_SSH_ALLOW=1\n", HostProfile::Linux).is_err());
        let (cfg, _) = build(
            "FAIL_CLOSED_SSH_ALLOW=1\nFAIL_CLOSED_SSH_ALLOW_CIDRS=10.0.0.0/8 192.168.0.0/16\n",
            HostProfile::Linux,
        )
        .unwrap();
        assert!(cfg.fail_closed_ssh_allow);
        assert_eq!(cfg.fail_closed_ssh_cidrs.len(), 2);
    }

    #[test]
    fn bad_port_and_lease_are_rejected() {
        assert!(build("WG_LISTEN_PORT=0\n", HostProfile::Linux).is_err());
        assert!(build("WG_LISTEN_PORT=70000\n", HostProfile::Linux).is_err());
        assert!(build("AUTO_PORT_FORWARD_LEASE_SECS=30\n", HostProfile::Linux).is_err());
        assert!(build("AUTO_TUNNEL_MAX_AGE_SECS=notnum\n", HostProfile::Linux).is_err());
    }

    #[test]
    fn wrong_backend_for_host_is_rejected() {
        assert!(build("BACKEND_MODE=macos-wireguard\n", HostProfile::Linux).is_err());
        assert!(build("BACKEND_MODE=linux-wireguard\n", HostProfile::Linux).is_ok());
    }

    #[test]
    fn preset_coerces_role_and_round_trips_serialization() {
        let (cfg, _) = build(
            "NODE_ROLE=client\nSETUP_ROLE_PRESET=exit\nSETUP_COMPLETE=1\n",
            HostProfile::Linux,
        )
        .unwrap();
        assert_eq!(cfg.node_role, NodeRole::Admin);
        let text = to_wizard_env(&cfg);
        let (cfg2, _) = build(&text, HostProfile::Linux).unwrap();
        assert_eq!(cfg.node_role, cfg2.node_role);
        assert_eq!(cfg.backend_mode, cfg2.backend_mode);
        assert_eq!(cfg.wg_listen_port, cfg2.wg_listen_port);
    }

    #[test]
    fn admin_only_profile_downgraded_for_client() {
        let (cfg, warnings) = build(
            "NODE_ROLE=client\nDEFAULT_LAUNCH_PROFILE=quick-hybrid\n",
            HostProfile::Linux,
        )
        .unwrap();
        assert_eq!(cfg.default_launch_profile, LaunchProfile::QuickConnect);
        assert!(warnings.iter().any(|msg| msg.contains("admin-only")));
    }
}
