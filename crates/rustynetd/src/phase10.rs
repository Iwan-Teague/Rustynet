#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::privileged_helper::{
    PrivilegedCommandClient, PrivilegedCommandOutput, PrivilegedCommandProgram,
};
use rustynet_backend_api::{
    BackendError, BackendErrorKind, ExitMode, NodeId, PeerConfig, Route, RuntimeContext,
    TunnelBackend,
};
use rustynet_policy::{
    ContextualAccessRequest, ContextualPolicySet, Decision, Protocol, TrafficContext,
};

const IP_BINARY_PATH_ENV: &str = "RUSTYNET_IP_BINARY_PATH";
const NFT_BINARY_PATH_ENV: &str = "RUSTYNET_NFT_BINARY_PATH";
const WG_BINARY_PATH_ENV: &str = "RUSTYNET_WG_BINARY_PATH";
const SYSCTL_BINARY_PATH_ENV: &str = "RUSTYNET_SYSCTL_BINARY_PATH";
const IFCONFIG_BINARY_PATH_ENV: &str = "RUSTYNET_IFCONFIG_BINARY_PATH";
const ROUTE_BINARY_PATH_ENV: &str = "RUSTYNET_ROUTE_BINARY_PATH";
const PFCTL_BINARY_PATH_ENV: &str = "RUSTYNET_PFCTL_BINARY_PATH";
const WIREGUARD_GO_BINARY_PATH_ENV: &str = "RUSTYNET_WIREGUARD_GO_BINARY_PATH";
const KILL_BINARY_PATH_ENV: &str = "RUSTYNET_KILL_BINARY_PATH";
const DEFAULT_IP_BINARY_PATH: &str = "/usr/sbin/ip";
const DEFAULT_NFT_BINARY_PATH: &str = "/usr/sbin/nft";
const DEFAULT_WG_BINARY_PATH: &str = "/usr/bin/wg";
const DEFAULT_SYSCTL_BINARY_PATH: &str = "/usr/sbin/sysctl";
const DEFAULT_IFCONFIG_BINARY_PATH: &str = "/sbin/ifconfig";
const DEFAULT_ROUTE_BINARY_PATH: &str = "/sbin/route";
const DEFAULT_PFCTL_BINARY_PATH: &str = "/sbin/pfctl";
const DEFAULT_WIREGUARD_GO_BINARY_PATH: &str = "/usr/local/bin/wireguard-go";
const DEFAULT_KILL_BINARY_PATH: &str = "/bin/kill";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataplaneState {
    Init,
    ControlTrusted,
    DataplaneApplied,
    ExitActive,
    FailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMode {
    Direct,
    Relay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionEvent {
    pub from_state: DataplaneState,
    pub to_state: DataplaneState,
    pub reason: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustEvidence {
    pub tls13_valid: bool,
    pub signed_control_valid: bool,
    pub signed_data_age_secs: u64,
    pub clock_skew_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustPolicy {
    pub max_signed_data_age_secs: u64,
    pub max_clock_skew_secs: u64,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            max_signed_data_age_secs: 300,
            max_clock_skew_secs: 90,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyOptions {
    pub protected_dns: bool,
    pub ipv6_parity_supported: bool,
    pub exit_mode: ExitMode,
    pub serve_exit_node: bool,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        Self {
            protected_dns: true,
            ipv6_parity_supported: false,
            exit_mode: ExitMode::Off,
            serve_exit_node: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteGrantRequest {
    pub user: String,
    pub cidr: String,
    pub protocol: Protocol,
    pub context: TrafficContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemError {
    PrerequisiteCheckFailed(String),
    RouteApplyFailed(String),
    FirewallApplyFailed(String),
    NatApplyFailed(String),
    DnsApplyFailed(String),
    KillSwitchAssertionFailed(String),
    BlockEgressFailed(String),
    RollbackFailed(String),
    Io(String),
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemError::PrerequisiteCheckFailed(message) => {
                write!(f, "prerequisite check failed: {message}")
            }
            SystemError::RouteApplyFailed(message) => write!(f, "route apply failed: {message}"),
            SystemError::FirewallApplyFailed(message) => {
                write!(f, "firewall apply failed: {message}")
            }
            SystemError::NatApplyFailed(message) => write!(f, "nat apply failed: {message}"),
            SystemError::DnsApplyFailed(message) => write!(f, "dns apply failed: {message}"),
            SystemError::KillSwitchAssertionFailed(message) => {
                write!(f, "killswitch assertion failed: {message}")
            }
            SystemError::BlockEgressFailed(message) => {
                write!(f, "block egress failed: {message}")
            }
            SystemError::RollbackFailed(message) => write!(f, "rollback failed: {message}"),
            SystemError::Io(message) => write!(f, "i/o failed: {message}"),
        }
    }
}

impl std::error::Error for SystemError {}

#[derive(Debug, PartialEq, Eq)]
pub enum Phase10Error {
    InvalidTransition(&'static str),
    TrustRejected(&'static str),
    Backend(BackendError),
    System(SystemError),
    PolicyDenied,
    ExitNotSelected,
    LanAccessDenied,
    NotStarted,
}

impl fmt::Display for Phase10Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Phase10Error::InvalidTransition(msg) => write!(f, "invalid transition: {msg}"),
            Phase10Error::TrustRejected(msg) => write!(f, "trust rejected: {msg}"),
            Phase10Error::Backend(err) => write!(f, "backend error: {err}"),
            Phase10Error::System(err) => write!(f, "system error: {err}"),
            Phase10Error::PolicyDenied => f.write_str("policy denied"),
            Phase10Error::ExitNotSelected => f.write_str("exit node not selected"),
            Phase10Error::LanAccessDenied => f.write_str("lan access denied"),
            Phase10Error::NotStarted => f.write_str("phase10 controller not started"),
        }
    }
}

impl std::error::Error for Phase10Error {}

impl From<BackendError> for Phase10Error {
    fn from(value: BackendError) -> Self {
        Phase10Error::Backend(value)
    }
}

impl From<SystemError> for Phase10Error {
    fn from(value: SystemError) -> Self {
        Phase10Error::System(value)
    }
}

pub trait DataplaneSystem {
    fn set_generation(&mut self, _generation: u64) {}
    fn set_relay_forwarding(&mut self, _enabled: bool) {}
    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        Ok(())
    }
    fn check_prerequisites(&mut self) -> Result<(), SystemError>;
    fn apply_peer_endpoint_bypass_routes(
        &mut self,
        _peers: &[PeerConfig],
    ) -> Result<(), SystemError> {
        Ok(())
    }
    fn apply_routes(&mut self, routes: &[Route]) -> Result<(), SystemError>;
    fn rollback_routes(&mut self) -> Result<(), SystemError>;
    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError>;
    fn rollback_firewall(&mut self) -> Result<(), SystemError>;
    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError>;
    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError>;
    fn apply_dns_protection(&mut self) -> Result<(), SystemError>;
    fn rollback_dns_protection(&mut self) -> Result<(), SystemError>;
    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError>;
    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        Ok(())
    }
    fn assert_killswitch(&mut self) -> Result<(), SystemError>;
    fn block_all_egress(&mut self) -> Result<(), SystemError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StageMarker {
    BackendStarted,
    PeerApplied,
    EndpointBypassApplied,
    BackendRoutesApplied,
    SystemRoutesApplied,
    FirewallApplied,
    NatApplied,
    DnsApplied,
    ExitModeApplied,
    Ipv6Blocked,
}

#[derive(Debug, Default)]
pub struct DryRunSystem {
    pub operations: Vec<String>,
    fail_operation: Option<String>,
    generation: u64,
    relay_forwarding_enabled: bool,
}

impl DryRunSystem {
    pub fn fail_on(mut self, operation: &str) -> Self {
        self.fail_operation = Some(operation.to_string());
        self
    }

    fn step(&mut self, operation: &str) -> Result<(), SystemError> {
        self.operations.push(operation.to_string());
        if self
            .fail_operation
            .as_ref()
            .map(|candidate| candidate == operation)
            .unwrap_or(false)
        {
            return Err(SystemError::RollbackFailed(operation.to_string()));
        }
        Ok(())
    }
}

impl DataplaneSystem for DryRunSystem {
    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
        self.operations.push(format!("set_generation:{generation}"));
    }

    fn set_relay_forwarding(&mut self, enabled: bool) {
        self.relay_forwarding_enabled = enabled;
        self.operations
            .push(format!("set_relay_forwarding:{enabled}"));
    }

    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        self.step("prune_owned_tables")
    }

    fn check_prerequisites(&mut self) -> Result<(), SystemError> {
        self.step("check_prerequisites")
    }

    fn apply_routes(&mut self, _routes: &[Route]) -> Result<(), SystemError> {
        self.step("apply_routes")
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        self.step("rollback_routes")
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        self.step("apply_firewall_killswitch")
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        self.step("rollback_firewall")
    }

    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.step("apply_nat_forwarding")
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.step("rollback_nat_forwarding")
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        self.step("apply_dns_protection")
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        self.step("rollback_dns_protection")
    }

    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.step("hard_disable_ipv6_egress")
    }

    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.step("rollback_ipv6_egress")
    }

    fn assert_killswitch(&mut self) -> Result<(), SystemError> {
        self.step("assert_killswitch")
    }

    fn block_all_egress(&mut self) -> Result<(), SystemError> {
        self.step("block_all_egress")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCommandSystem {
    interface_name: String,
    egress_interface: String,
    mode: LinuxDataplaneMode,
    privileged_client: Option<PrivilegedCommandClient>,
    generation: u64,
    fail_closed_ssh_allow: bool,
    fail_closed_ssh_allow_cidrs: Vec<String>,
    firewall_table: Option<String>,
    nat_table: Option<String>,
    prior_ipv4_forwarding: Option<bool>,
    prior_ipv6_disabled: Option<bool>,
    allow_tunnel_relay_forward: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxDataplaneMode {
    Shell,
    HybridNative,
}

impl LinuxCommandSystem {
    pub fn new(
        interface_name: impl Into<String>,
        egress_interface: impl Into<String>,
        mode: LinuxDataplaneMode,
        privileged_client: Option<PrivilegedCommandClient>,
        fail_closed_ssh_allow: bool,
        fail_closed_ssh_allow_cidrs: Vec<String>,
    ) -> Result<Self, SystemError> {
        let interface_name = interface_name.into();
        let egress_interface = egress_interface.into();
        validate_net_device_name(&interface_name)
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_string()))?;
        validate_net_device_name(&egress_interface)
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_string()))?;
        if fail_closed_ssh_allow && fail_closed_ssh_allow_cidrs.is_empty() {
            return Err(SystemError::PrerequisiteCheckFailed(
                "fail-closed ssh allow is enabled but no management cidrs were provided"
                    .to_string(),
            ));
        }

        Ok(Self {
            interface_name,
            egress_interface,
            mode,
            privileged_client,
            generation: 0,
            fail_closed_ssh_allow,
            fail_closed_ssh_allow_cidrs,
            firewall_table: None,
            nat_table: None,
            prior_ipv4_forwarding: None,
            prior_ipv6_disabled: None,
            allow_tunnel_relay_forward: false,
        })
    }

    fn run(&self, program: PrivilegedCommandProgram, args: &[&str]) -> Result<(), SystemError> {
        let output = self.run_capture(program, args)?;
        if output.success() {
            return Ok(());
        }
        Err(SystemError::Io(format!(
            "{} exited unsuccessfully: status={} stderr={}",
            program.as_str(),
            output.status,
            output.stderr
        )))
    }

    fn run_allow_failure(&self, program: PrivilegedCommandProgram, args: &[&str]) {
        let _ = self.run_capture(program, args);
    }

    fn run_capture(
        &self,
        program: PrivilegedCommandProgram,
        args: &[&str],
    ) -> Result<PrivilegedCommandOutput, SystemError> {
        if let Some(client) = self.privileged_client.as_ref() {
            return client.run_capture(program, args).map_err(SystemError::Io);
        }

        let binary = resolve_binary_path_for_program(program).map_err(|err| {
            SystemError::Io(format!(
                "{} binary resolution failed: {err}",
                program.as_str()
            ))
        })?;
        let output = Command::new(&binary).args(args).output().map_err(|err| {
            SystemError::Io(format!(
                "{} spawn failed ({}): {err}",
                program.as_str(),
                binary.display()
            ))
        })?;
        Ok(PrivilegedCommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    fn nft_family_for_cidr(cidr: &str) -> Option<&'static str> {
        let (base, prefix) = cidr.split_once('/')?;
        if prefix.parse::<u8>().is_err() {
            return None;
        }
        match base.parse::<IpAddr>().ok()? {
            IpAddr::V4(_) => Some("ip"),
            IpAddr::V6(_) => Some("ip6"),
        }
    }

    fn apply_fail_closed_management_allow_rules(&self, table: &str) -> Result<(), SystemError> {
        if !self.fail_closed_ssh_allow {
            return Ok(());
        }
        for cidr in &self.fail_closed_ssh_allow_cidrs {
            let family = Self::nft_family_for_cidr(cidr).ok_or_else(|| {
                SystemError::FirewallApplyFailed(format!("invalid management cidr: {cidr}"))
            })?;
            self.run(
                PrivilegedCommandProgram::Nft,
                &[
                    "add",
                    "rule",
                    "inet",
                    table,
                    "killswitch",
                    family,
                    "daddr",
                    cidr.as_str(),
                    "tcp",
                    "sport",
                    "22",
                    "accept",
                ],
            )
            .map_err(|err| {
                SystemError::FirewallApplyFailed(format!(
                    "management ssh fail-closed allow rule failed for {cidr}: {err}"
                ))
            })?;
        }
        Ok(())
    }

    fn apply_fail_closed_management_bypass_routes(&self) -> Result<(), SystemError> {
        if !self.fail_closed_ssh_allow {
            return Ok(());
        }
        for cidr in &self.fail_closed_ssh_allow_cidrs {
            let args = Self::management_bypass_route_args(cidr, self.egress_interface.as_str());
            let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            let result = self.run(PrivilegedCommandProgram::Ip, &arg_refs);
            result.map_err(|err| {
                SystemError::RouteApplyFailed(format!(
                    "management ssh bypass route failed for {cidr}: {err}"
                ))
            })?;
        }
        Ok(())
    }

    fn management_bypass_route_args(cidr: &str, egress_interface: &str) -> Vec<String> {
        let mut args = Vec::with_capacity(9);
        if cidr.contains(':') {
            args.push("-6".to_string());
        }
        args.push("route".to_string());
        args.push("replace".to_string());
        args.push(cidr.to_string());
        args.push("dev".to_string());
        args.push(egress_interface.to_string());
        args.push("table".to_string());
        args.push("51820".to_string());
        args
    }

    fn peer_endpoint_bypass_route_args(addr: IpAddr, egress_interface: &str) -> Vec<String> {
        let endpoint_cidr = match addr {
            IpAddr::V4(value) => format!("{value}/32"),
            IpAddr::V6(value) => format!("{value}/128"),
        };
        let mut args = Vec::with_capacity(9);
        if matches!(addr, IpAddr::V6(_)) {
            args.push("-6".to_string());
        }
        args.push("route".to_string());
        args.push("replace".to_string());
        args.push(endpoint_cidr);
        args.push("dev".to_string());
        args.push(egress_interface.to_string());
        args.push("table".to_string());
        args.push("51820".to_string());
        args
    }

    fn set_ipv4_forwarding(&self, enabled: bool) -> Result<(), SystemError> {
        let use_native_write = matches!(self.mode, LinuxDataplaneMode::HybridNative)
            && self.privileged_client.is_none();
        if use_native_write {
            return fs::write(
                "/proc/sys/net/ipv4/ip_forward",
                if enabled { "1\n" } else { "0\n" },
            )
            .map_err(|err| SystemError::Io(format!("native ip_forward write failed: {err}")));
        }
        self.run(
            PrivilegedCommandProgram::Sysctl,
            &[
                "-w",
                if enabled {
                    "net.ipv4.ip_forward=1"
                } else {
                    "net.ipv4.ip_forward=0"
                },
            ],
        )
    }

    fn set_ipv6_disabled(&self, disabled: bool) -> Result<(), SystemError> {
        let use_native_write = matches!(self.mode, LinuxDataplaneMode::HybridNative)
            && self.privileged_client.is_none();
        if use_native_write {
            return fs::write(
                "/proc/sys/net/ipv6/conf/all/disable_ipv6",
                if disabled { "1\n" } else { "0\n" },
            )
            .map_err(|err| SystemError::Io(format!("native ipv6 disable write failed: {err}")));
        }
        self.run(
            PrivilegedCommandProgram::Sysctl,
            &[
                "-w",
                if disabled {
                    "net.ipv6.conf.all.disable_ipv6=1"
                } else {
                    "net.ipv6.conf.all.disable_ipv6=0"
                },
            ],
        )
    }

    fn firewall_table_name(&self) -> String {
        format!("rustynet_g{}", self.generation)
    }

    fn nat_table_name(&self) -> String {
        format!("rustynet_nat_g{}", self.generation)
    }

    fn ensure_failclosed_table(&mut self) -> Result<String, SystemError> {
        if let Some(table) = self.firewall_table.clone() {
            if self.killswitch_chain_exists(table.as_str())? {
                return Ok(table);
            }
            // A prior generation table can be pruned before fail-closed recovery runs.
            // Drop stale state so we can recreate a valid fail-closed table/chain.
            self.firewall_table = None;
        }

        let table = self.firewall_table_name();
        self.run_allow_failure(
            PrivilegedCommandProgram::Nft,
            &["delete", "table", "inet", table.as_str()],
        );
        self.run(
            PrivilegedCommandProgram::Nft,
            &["add", "table", "inet", table.as_str()],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "chain",
                "inet",
                table.as_str(),
                "killswitch",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "0",
                ";",
                "policy",
                "drop",
                ";",
                "}",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.apply_fail_closed_management_allow_rules(table.as_str())?;
        self.firewall_table = Some(table.clone());
        Ok(table)
    }

    fn read_sysctl_bool(path: &str, key: &str) -> Result<bool, SystemError> {
        let raw = fs::read_to_string(path)
            .map_err(|err| SystemError::Io(format!("read {key} failed: {err}")))?;
        let value = raw.trim();
        match value {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(SystemError::Io(format!("unexpected {key} value: {value}"))),
        }
    }

    fn restore_ipv4_forwarding(&mut self) -> Result<(), SystemError> {
        if let Some(previous) = self.prior_ipv4_forwarding.take() {
            self.set_ipv4_forwarding(previous)
                .map_err(|err| SystemError::RollbackFailed(err.to_string()))?;
        }
        Ok(())
    }

    fn list_tables(&self) -> Result<Vec<(String, String)>, SystemError> {
        let output = self.run_capture(PrivilegedCommandProgram::Nft, &["list", "tables"])?;
        if !output.success() {
            return Err(SystemError::Io(format!(
                "nft list tables exited unsuccessfully: status={} stderr={}",
                output.status, output.stderr
            )));
        }
        let mut tables = Vec::new();
        for line in output.stdout.lines() {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() == 3 && parts[0] == "table" {
                tables.push((parts[1].to_string(), parts[2].to_string()));
            }
        }
        Ok(tables)
    }

    fn has_fail_closed_drop_rule(&self, table: &str) -> Result<bool, SystemError> {
        let output = self.run_capture(
            PrivilegedCommandProgram::Nft,
            &["list", "chain", "inet", table, "killswitch"],
        )?;
        if !output.success() {
            if Self::is_nft_missing_object_error(output.stderr.as_str()) {
                return Ok(false);
            }
            return Err(SystemError::BlockEgressFailed(format!(
                "nft list chain exited unsuccessfully: status={} stderr={}",
                output.status, output.stderr
            )));
        }
        Ok(output
            .stdout
            .contains("comment \"rustynet_fail_closed_drop\""))
    }

    fn killswitch_chain_exists(&self, table: &str) -> Result<bool, SystemError> {
        let output = self.run_capture(
            PrivilegedCommandProgram::Nft,
            &["list", "chain", "inet", table, "killswitch"],
        )?;
        if output.success() {
            return Ok(true);
        }
        if Self::is_nft_missing_object_error(output.stderr.as_str()) {
            return Ok(false);
        }
        Err(SystemError::Io(format!(
            "nft list chain exited unsuccessfully: status={} stderr={}",
            output.status, output.stderr
        )))
    }

    fn is_nft_missing_object_error(stderr: &str) -> bool {
        stderr
            .to_ascii_lowercase()
            .contains("no such file or directory")
    }
}

impl DataplaneSystem for LinuxCommandSystem {
    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn set_relay_forwarding(&mut self, enabled: bool) {
        self.allow_tunnel_relay_forward = enabled;
    }

    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        let keep_firewall = self.firewall_table_name();
        let keep_nat = self.nat_table_name();
        for (family, table) in self.list_tables()? {
            let is_owned = (family == "inet" && table.starts_with("rustynet_g"))
                || (family == "ip" && table.starts_with("rustynet_nat_g"));
            if !is_owned {
                continue;
            }
            if (family == "inet" && table == keep_firewall) || (family == "ip" && table == keep_nat)
            {
                continue;
            }
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", family.as_str(), table.as_str()],
            );
        }
        Ok(())
    }

    fn check_prerequisites(&mut self) -> Result<(), SystemError> {
        #[cfg(target_os = "linux")]
        {
            self.run(PrivilegedCommandProgram::Ip, &["-V"])?;
            self.run(PrivilegedCommandProgram::Nft, &["--version"])?;
            self.run(PrivilegedCommandProgram::Wg, &["--version"])?;
            self.run(PrivilegedCommandProgram::Sysctl, &["--version"])?;
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err(SystemError::PrerequisiteCheckFailed(
            "linux command system is only supported on linux".to_string(),
        ))
    }

    fn apply_peer_endpoint_bypass_routes(
        &mut self,
        peers: &[PeerConfig],
    ) -> Result<(), SystemError> {
        let mut endpoints = BTreeSet::new();
        for peer in peers {
            endpoints.insert(peer.endpoint.addr);
        }
        for endpoint in endpoints {
            let args =
                Self::peer_endpoint_bypass_route_args(endpoint, self.egress_interface.as_str());
            let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            self.run(PrivilegedCommandProgram::Ip, &arg_refs)
                .map_err(|err| {
                    SystemError::RouteApplyFailed(format!(
                        "peer endpoint bypass route failed for {endpoint}: {err}"
                    ))
                })?;
        }
        Ok(())
    }

    fn apply_routes(&mut self, routes: &[Route]) -> Result<(), SystemError> {
        self.apply_fail_closed_management_bypass_routes()?;
        for route in routes {
            self.run(
                PrivilegedCommandProgram::Ip,
                &[
                    "route",
                    "replace",
                    route.destination_cidr.as_str(),
                    "dev",
                    self.interface_name.as_str(),
                    "table",
                    "51820",
                ],
            )
            .map_err(|err| SystemError::RouteApplyFailed(err.to_string()))?;
        }
        Ok(())
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        // `ip route flush table 51820` exits non-zero when the table is absent,
        // which is an acceptable rollback outcome on a fresh host.
        self.run_allow_failure(
            PrivilegedCommandProgram::Ip,
            &["route", "flush", "table", "51820"],
        );
        Ok(())
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        if let Some(previous) = self.firewall_table.take() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "inet", previous.as_str()],
            );
        }
        let table = self.ensure_failclosed_table()?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "chain",
                "inet",
                table.as_str(),
                "forward",
                "{",
                "type",
                "filter",
                "hook",
                "forward",
                "priority",
                "0",
                ";",
                "policy",
                "drop",
                ";",
                "}",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "oifname",
                "lo",
                "accept",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "ct",
                "state",
                "established,related",
                "accept",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "oifname",
                self.interface_name.as_str(),
                "accept",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "forward",
                "ct",
                "state",
                "established,related",
                "accept",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "forward",
                "iifname",
                self.interface_name.as_str(),
                "oifname",
                self.egress_interface.as_str(),
                "accept",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        if self.allow_tunnel_relay_forward {
            self.run(
                PrivilegedCommandProgram::Nft,
                &[
                    "add",
                    "rule",
                    "inet",
                    table.as_str(),
                    "forward",
                    "iifname",
                    self.interface_name.as_str(),
                    "oifname",
                    self.interface_name.as_str(),
                    "accept",
                ],
            )
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        }
        Ok(())
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        if let Some(table) = self.firewall_table.take() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "inet", table.as_str()],
            );
        }
        Ok(())
    }

    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.prior_ipv4_forwarding = Some(Self::read_sysctl_bool(
            "/proc/sys/net/ipv4/ip_forward",
            "net.ipv4.ip_forward",
        )?);
        self.set_ipv4_forwarding(true)
            .map_err(|err| SystemError::NatApplyFailed(err.to_string()))?;

        if let Some(previous) = self.nat_table.take() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "ip", previous.as_str()],
            );
        }
        let nat_table = self.nat_table_name();
        if let Err(err) = self.run(
            PrivilegedCommandProgram::Nft,
            &["add", "table", "ip", nat_table.as_str()],
        ) {
            let _ = self.restore_ipv4_forwarding();
            return Err(SystemError::NatApplyFailed(err.to_string()));
        }
        if let Err(err) = self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "chain",
                "ip",
                nat_table.as_str(),
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "100",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
        ) {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "ip", nat_table.as_str()],
            );
            let _ = self.restore_ipv4_forwarding();
            return Err(SystemError::NatApplyFailed(err.to_string()));
        }
        if let Err(err) = self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "ip",
                nat_table.as_str(),
                "postrouting",
                "oifname",
                self.egress_interface.as_str(),
                "masquerade",
            ],
        ) {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "ip", nat_table.as_str()],
            );
            let _ = self.restore_ipv4_forwarding();
            return Err(SystemError::NatApplyFailed(err.to_string()));
        }
        if self.allow_tunnel_relay_forward {
            match self.run(
                PrivilegedCommandProgram::Nft,
                &[
                    "add",
                    "rule",
                    "ip",
                    nat_table.as_str(),
                    "postrouting",
                    "iifname",
                    self.interface_name.as_str(),
                    "oifname",
                    self.interface_name.as_str(),
                    "masquerade",
                ],
            ) {
                Ok(()) => {}
                Err(err) => {
                    self.run_allow_failure(
                        PrivilegedCommandProgram::Nft,
                        &["delete", "table", "ip", nat_table.as_str()],
                    );
                    let _ = self.restore_ipv4_forwarding();
                    return Err(SystemError::NatApplyFailed(err.to_string()));
                }
            }
        }
        // Collect firewall table name and egress interface before moving nat_table.
        let egress_allow = self
            .firewall_table
            .as_ref()
            .map(|fw| (fw.clone(), self.egress_interface.clone()));

        self.nat_table = Some(nat_table);

        // Allow the exit node device's own outbound traffic via the egress interface.
        // The killswitch chain has policy drop on the OUTPUT hook; without this rule
        // the exit node device itself cannot open new connections to the internet
        // while acting as an exit node.
        if let Some((fw_table, egress_iface)) = egress_allow {
            let nat_name = self.nat_table.as_deref().unwrap_or("").to_string();
            if let Err(err) = self.run(
                PrivilegedCommandProgram::Nft,
                &[
                    "add",
                    "rule",
                    "inet",
                    fw_table.as_str(),
                    "killswitch",
                    "oifname",
                    egress_iface.as_str(),
                    "accept",
                ],
            ) {
                self.run_allow_failure(
                    PrivilegedCommandProgram::Nft,
                    &["delete", "table", "ip", nat_name.as_str()],
                );
                self.nat_table = None;
                let _ = self.restore_ipv4_forwarding();
                return Err(SystemError::NatApplyFailed(format!(
                    "egress access rule failed: {err}"
                )));
            }
        }

        Ok(())
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        if let Some(table) = self.nat_table.take() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "ip", table.as_str()],
            );
        }
        self.restore_ipv4_forwarding()
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        let table = self
            .firewall_table
            .clone()
            .ok_or_else(|| SystemError::DnsApplyFailed("killswitch table missing".to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "udp",
                "dport",
                "53",
                "oifname",
                "!=",
                self.interface_name.as_str(),
                "drop",
            ],
        )
        .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "tcp",
                "dport",
                "53",
                "oifname",
                "!=",
                self.interface_name.as_str(),
                "drop",
            ],
        )
        .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "udp",
                "dport",
                "53",
                "accept",
            ],
        )
        .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "tcp",
                "dport",
                "53",
                "accept",
            ],
        )
        .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        Ok(())
    }

    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.prior_ipv6_disabled = Some(Self::read_sysctl_bool(
            "/proc/sys/net/ipv6/conf/all/disable_ipv6",
            "net.ipv6.conf.all.disable_ipv6",
        )?);
        self.set_ipv6_disabled(true)
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))
    }

    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        if let Some(previous) = self.prior_ipv6_disabled.take() {
            self.set_ipv6_disabled(previous)
                .map_err(|err| SystemError::RollbackFailed(err.to_string()))?;
        }
        Ok(())
    }

    fn assert_killswitch(&mut self) -> Result<(), SystemError> {
        let table = self.firewall_table.clone().ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("killswitch table missing".to_string())
        })?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &["list", "table", "inet", table.as_str()],
        )
        .map_err(|err| SystemError::KillSwitchAssertionFailed(err.to_string()))
    }

    fn block_all_egress(&mut self) -> Result<(), SystemError> {
        let table = self.ensure_failclosed_table()?;
        if self.has_fail_closed_drop_rule(table.as_str())? {
            return Ok(());
        }
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "counter",
                "drop",
                "comment",
                "rustynet_fail_closed_drop",
            ],
        )
        .map_err(|err| SystemError::BlockEgressFailed(err.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosCommandSystem {
    interface_name: String,
    egress_interface: String,
    privileged_client: Option<PrivilegedCommandClient>,
    generation: u64,
    fail_closed_ssh_allow: bool,
    fail_closed_ssh_allow_cidrs: Vec<String>,
    anchor_name: Option<String>,
    allow_egress_interface: bool,
    ipv6_blocked: bool,
    dns_protected: bool,
}

impl MacosCommandSystem {
    pub fn new(
        interface_name: impl Into<String>,
        egress_interface: impl Into<String>,
        privileged_client: Option<PrivilegedCommandClient>,
        fail_closed_ssh_allow: bool,
        fail_closed_ssh_allow_cidrs: Vec<String>,
    ) -> Result<Self, SystemError> {
        let interface_name = interface_name.into();
        let egress_interface = egress_interface.into();
        validate_net_device_name(&interface_name)
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_string()))?;
        validate_net_device_name(&egress_interface)
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_string()))?;
        if fail_closed_ssh_allow && fail_closed_ssh_allow_cidrs.is_empty() {
            return Err(SystemError::PrerequisiteCheckFailed(
                "fail-closed ssh allow is enabled but no management cidrs were provided"
                    .to_string(),
            ));
        }
        Ok(Self {
            interface_name,
            egress_interface,
            privileged_client,
            generation: 0,
            fail_closed_ssh_allow,
            fail_closed_ssh_allow_cidrs,
            anchor_name: None,
            allow_egress_interface: false,
            ipv6_blocked: false,
            dns_protected: false,
        })
    }

    fn run(&self, program: PrivilegedCommandProgram, args: &[&str]) -> Result<(), SystemError> {
        let output = self.run_capture(program, args)?;
        if output.success() {
            return Ok(());
        }
        Err(SystemError::Io(format!(
            "{} exited unsuccessfully: status={} stderr={}",
            program.as_str(),
            output.status,
            output.stderr
        )))
    }

    fn run_allow_failure(&self, program: PrivilegedCommandProgram, args: &[&str]) {
        let _ = self.run_capture(program, args);
    }

    fn run_capture(
        &self,
        program: PrivilegedCommandProgram,
        args: &[&str],
    ) -> Result<PrivilegedCommandOutput, SystemError> {
        if let Some(client) = self.privileged_client.as_ref() {
            return client.run_capture(program, args).map_err(SystemError::Io);
        }

        let binary = resolve_binary_path_for_program(program).map_err(|err| {
            SystemError::Io(format!(
                "{} binary resolution failed: {err}",
                program.as_str()
            ))
        })?;
        let output = Command::new(&binary).args(args).output().map_err(|err| {
            SystemError::Io(format!(
                "{} spawn failed ({}): {err}",
                program.as_str(),
                binary.display()
            ))
        })?;
        Ok(PrivilegedCommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    fn current_anchor_name(&self) -> String {
        format!("com.apple/rustynet_g{}", self.generation)
    }

    fn ensure_pf_enabled(&self) -> Result<(), SystemError> {
        let info = self.run_capture(PrivilegedCommandProgram::Pfctl, &["-s", "info"])?;
        if info.success() && info.stdout.contains("Status: Enabled") {
            return Ok(());
        }
        self.run(PrivilegedCommandProgram::Pfctl, &["-E"])
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))
    }

    fn management_cidr_family(cidr: &str) -> Result<&'static str, SystemError> {
        let (base, prefix) = cidr.split_once('/').ok_or_else(|| {
            SystemError::FirewallApplyFailed(format!("invalid management cidr: {cidr}"))
        })?;
        let prefix_valid = prefix.parse::<u8>().is_ok();
        if !prefix_valid {
            return Err(SystemError::FirewallApplyFailed(format!(
                "invalid management cidr prefix: {cidr}"
            )));
        }
        match base.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => Ok("inet"),
            Ok(IpAddr::V6(_)) => Ok("inet6"),
            Err(_) => Err(SystemError::FirewallApplyFailed(format!(
                "invalid management cidr: {cidr}"
            ))),
        }
    }

    fn render_pf_rules(&self, strict_fail_closed: bool) -> Result<String, SystemError> {
        let mut rules = String::new();
        rules.push_str("set block-policy drop\n");
        if !strict_fail_closed {
            rules.push_str("pass out quick inet on lo0 all keep state\n");
            if self.dns_protected {
                rules.push_str(&format!(
                    "pass out quick inet proto udp on {} to any port 53 keep state\n",
                    self.interface_name
                ));
                rules.push_str(&format!(
                    "pass out quick inet proto tcp on {} to any port 53 keep state\n",
                    self.interface_name
                ));
                rules.push_str("block drop out quick inet proto udp to any port 53\n");
                rules.push_str("block drop out quick inet proto tcp to any port 53\n");
            }
            rules.push_str(&format!(
                "pass out quick inet on {} all keep state\n",
                self.interface_name
            ));
            if self.allow_egress_interface {
                rules.push_str(&format!(
                    "pass out quick inet on {} all keep state\n",
                    self.egress_interface
                ));
            }
        }
        if self.fail_closed_ssh_allow {
            for cidr in &self.fail_closed_ssh_allow_cidrs {
                let family = Self::management_cidr_family(cidr)?;
                rules.push_str(&format!(
                    "pass out quick {} proto tcp from any port 22 to {} keep state\n",
                    family, cidr
                ));
            }
        }
        if self.ipv6_blocked {
            rules.push_str("block drop out quick inet6 all\n");
        }
        rules.push_str("block drop out quick all\n");
        Ok(rules)
    }

    fn ruleset_contains_dns_rule(
        rules: &str,
        action_token: &str,
        proto: &str,
        interface: Option<&str>,
    ) -> bool {
        let action = action_token.to_ascii_lowercase();
        let proto_token = format!("proto {proto}");
        let interface_token = interface.map(|value| format!("on {}", value.to_ascii_lowercase()));
        rules.lines().any(|line| {
            let normalized = line.trim().to_ascii_lowercase();
            if !normalized.contains(&action) {
                return false;
            }
            if !normalized.contains("inet") {
                return false;
            }
            if !normalized.contains(&proto_token) {
                return false;
            }
            match interface_token.as_ref() {
                Some(token) if !normalized.contains(token) => {
                    return false;
                }
                _ => {}
            }
            normalized.contains("port 53") || normalized.contains("port = domain")
        })
    }

    fn apply_pf_rules(&mut self, strict_fail_closed: bool) -> Result<(), SystemError> {
        self.ensure_pf_enabled()?;
        let next_anchor = self.current_anchor_name();
        match self.anchor_name.as_ref() {
            Some(previous) if previous != &next_anchor => {
                self.run_allow_failure(
                    PrivilegedCommandProgram::Pfctl,
                    &["-a", previous.as_str(), "-F", "all"],
                );
            }
            _ => {}
        }

        let tmp_path = std::env::temp_dir().join(format!(
            "rustynet-pf-rules-{}-{}.conf",
            std::process::id(),
            self.generation
        ));
        let rules = self.render_pf_rules(strict_fail_closed)?;
        fs::write(&tmp_path, rules)
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        let tmp = tmp_path
            .to_str()
            .ok_or_else(|| SystemError::FirewallApplyFailed("pf temp path utf8".to_string()))?;
        let apply_result = self.run(
            PrivilegedCommandProgram::Pfctl,
            &["-a", next_anchor.as_str(), "-f", tmp],
        );
        let _ = fs::remove_file(&tmp_path);
        apply_result.map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.anchor_name = Some(next_anchor);
        Ok(())
    }

    fn owned_anchor_names_from_output(stdout: &str) -> Vec<String> {
        stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && line.starts_with("com.apple/rustynet_g"))
            .map(ToOwned::to_owned)
            .collect()
    }

    fn list_owned_anchors(&self) -> Result<Vec<String>, SystemError> {
        let output = self.run_capture(PrivilegedCommandProgram::Pfctl, &["-s", "Anchors"])?;
        if output.success() {
            return Ok(Self::owned_anchor_names_from_output(&output.stdout));
        }
        let stderr = output.stderr.to_ascii_lowercase();
        if stderr.contains("pf not enabled") {
            return Ok(Vec::new());
        }
        Err(SystemError::Io(format!(
            "pfctl anchor query failed: status={} stderr={}",
            output.status, output.stderr
        )))
    }

    fn flush_anchor(&mut self) {
        if let Some(anchor) = self.anchor_name.take() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor.as_str(), "-F", "all"],
            );
        }
    }
}

impl DataplaneSystem for MacosCommandSystem {
    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        for anchor in self.list_owned_anchors()? {
            self.run_allow_failure(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor.as_str(), "-F", "all"],
            );
        }
        self.anchor_name = None;
        Ok(())
    }

    fn check_prerequisites(&mut self) -> Result<(), SystemError> {
        #[cfg(target_os = "macos")]
        {
            resolve_binary_path_for_program(PrivilegedCommandProgram::Wg)?;
            resolve_binary_path_for_program(PrivilegedCommandProgram::WireguardGo)?;
            resolve_binary_path_for_program(PrivilegedCommandProgram::Ifconfig)?;
            resolve_binary_path_for_program(PrivilegedCommandProgram::Route)?;
            resolve_binary_path_for_program(PrivilegedCommandProgram::Pfctl)?;
            self.run(PrivilegedCommandProgram::Ifconfig, &["-l"])?;
            self.run(PrivilegedCommandProgram::Route, &["-n", "get", "default"])?;
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err(SystemError::PrerequisiteCheckFailed(
            "macos command system is only supported on macos".to_string(),
        ))
    }

    fn apply_routes(&mut self, _routes: &[Route]) -> Result<(), SystemError> {
        Ok(())
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        Ok(())
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        self.allow_egress_interface = false;
        self.apply_pf_rules(false)
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        self.flush_anchor();
        Ok(())
    }

    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.allow_egress_interface = true;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::NatApplyFailed(err.to_string()))
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.allow_egress_interface = false;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::RollbackFailed(err.to_string()))
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        self.dns_protected = true;
        if let Err(err) = self.apply_pf_rules(false) {
            self.dns_protected = false;
            return Err(SystemError::DnsApplyFailed(err.to_string()));
        }
        Ok(())
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        self.dns_protected = false;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::RollbackFailed(err.to_string()))
    }

    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.ipv6_blocked = true;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))
    }

    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.ipv6_blocked = false;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::RollbackFailed(err.to_string()))
    }

    fn assert_killswitch(&mut self) -> Result<(), SystemError> {
        let anchor = self.anchor_name.clone().ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("pf anchor missing".to_string())
        })?;
        let output = self.run_capture(
            PrivilegedCommandProgram::Pfctl,
            &["-a", anchor.as_str(), "-s", "rules"],
        )?;
        if !output.success() {
            return Err(SystemError::KillSwitchAssertionFailed(format!(
                "pfctl rules query failed: status={} stderr={}",
                output.status, output.stderr
            )));
        }
        if !output.stdout.contains("block drop out quick all") {
            return Err(SystemError::KillSwitchAssertionFailed(
                "pf killswitch rule missing".to_string(),
            ));
        }
        if self.dns_protected {
            if !Self::ruleset_contains_dns_rule(
                &output.stdout,
                "pass out quick",
                "udp",
                Some(self.interface_name.as_str()),
            ) {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns udp allow rule missing".to_string(),
                ));
            }
            if !Self::ruleset_contains_dns_rule(
                &output.stdout,
                "pass out quick",
                "tcp",
                Some(self.interface_name.as_str()),
            ) {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns tcp allow rule missing".to_string(),
                ));
            }
            if !Self::ruleset_contains_dns_rule(&output.stdout, "block drop out quick", "udp", None)
            {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns udp block rule missing".to_string(),
                ));
            }
            if !Self::ruleset_contains_dns_rule(&output.stdout, "block drop out quick", "tcp", None)
            {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns tcp block rule missing".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn block_all_egress(&mut self) -> Result<(), SystemError> {
        self.apply_pf_rules(true)
            .map_err(|err| SystemError::BlockEgressFailed(err.to_string()))
    }
}

#[derive(Debug)]
pub enum RuntimeSystem {
    DryRun(DryRunSystem),
    Linux(LinuxCommandSystem),
    Macos(MacosCommandSystem),
}

impl DataplaneSystem for RuntimeSystem {
    fn set_generation(&mut self, generation: u64) {
        match self {
            RuntimeSystem::DryRun(system) => system.set_generation(generation),
            RuntimeSystem::Linux(system) => system.set_generation(generation),
            RuntimeSystem::Macos(system) => system.set_generation(generation),
        }
    }

    fn set_relay_forwarding(&mut self, enabled: bool) {
        match self {
            RuntimeSystem::DryRun(system) => system.set_relay_forwarding(enabled),
            RuntimeSystem::Linux(system) => system.set_relay_forwarding(enabled),
            RuntimeSystem::Macos(system) => system.set_relay_forwarding(enabled),
        }
    }

    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.prune_owned_tables(),
            RuntimeSystem::Linux(system) => system.prune_owned_tables(),
            RuntimeSystem::Macos(system) => system.prune_owned_tables(),
        }
    }

    fn check_prerequisites(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.check_prerequisites(),
            RuntimeSystem::Linux(system) => system.check_prerequisites(),
            RuntimeSystem::Macos(system) => system.check_prerequisites(),
        }
    }

    fn apply_peer_endpoint_bypass_routes(
        &mut self,
        peers: &[PeerConfig],
    ) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_peer_endpoint_bypass_routes(peers),
            RuntimeSystem::Linux(system) => system.apply_peer_endpoint_bypass_routes(peers),
            RuntimeSystem::Macos(system) => system.apply_peer_endpoint_bypass_routes(peers),
        }
    }

    fn apply_routes(&mut self, routes: &[Route]) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_routes(routes),
            RuntimeSystem::Linux(system) => system.apply_routes(routes),
            RuntimeSystem::Macos(system) => system.apply_routes(routes),
        }
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.rollback_routes(),
            RuntimeSystem::Linux(system) => system.rollback_routes(),
            RuntimeSystem::Macos(system) => system.rollback_routes(),
        }
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_firewall_killswitch(),
            RuntimeSystem::Linux(system) => system.apply_firewall_killswitch(),
            RuntimeSystem::Macos(system) => system.apply_firewall_killswitch(),
        }
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.rollback_firewall(),
            RuntimeSystem::Linux(system) => system.rollback_firewall(),
            RuntimeSystem::Macos(system) => system.rollback_firewall(),
        }
    }

    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_nat_forwarding(),
            RuntimeSystem::Linux(system) => system.apply_nat_forwarding(),
            RuntimeSystem::Macos(system) => system.apply_nat_forwarding(),
        }
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.rollback_nat_forwarding(),
            RuntimeSystem::Linux(system) => system.rollback_nat_forwarding(),
            RuntimeSystem::Macos(system) => system.rollback_nat_forwarding(),
        }
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_dns_protection(),
            RuntimeSystem::Linux(system) => system.apply_dns_protection(),
            RuntimeSystem::Macos(system) => system.apply_dns_protection(),
        }
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.rollback_dns_protection(),
            RuntimeSystem::Linux(system) => system.rollback_dns_protection(),
            RuntimeSystem::Macos(system) => system.rollback_dns_protection(),
        }
    }

    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.hard_disable_ipv6_egress(),
            RuntimeSystem::Linux(system) => system.hard_disable_ipv6_egress(),
            RuntimeSystem::Macos(system) => system.hard_disable_ipv6_egress(),
        }
    }

    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.rollback_ipv6_egress(),
            RuntimeSystem::Linux(system) => system.rollback_ipv6_egress(),
            RuntimeSystem::Macos(system) => system.rollback_ipv6_egress(),
        }
    }

    fn assert_killswitch(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.assert_killswitch(),
            RuntimeSystem::Linux(system) => system.assert_killswitch(),
            RuntimeSystem::Macos(system) => system.assert_killswitch(),
        }
    }

    fn block_all_egress(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.block_all_egress(),
            RuntimeSystem::Linux(system) => system.block_all_egress(),
            RuntimeSystem::Macos(system) => system.block_all_egress(),
        }
    }
}

pub struct Phase10Controller<B: TunnelBackend, S: DataplaneSystem> {
    backend: B,
    system: S,
    policy: ContextualPolicySet,
    trust_policy: TrustPolicy,
    state: DataplaneState,
    generation: u64,
    last_safe_generation: u64,
    transitions: Vec<TransitionEvent>,
    selected_exit_node: Option<NodeId>,
    lan_access_enabled: bool,
    advertised_lan_routes: HashMap<NodeId, BTreeSet<String>>,
    lan_route_acl: HashMap<(String, String), bool>,
    peer_paths: BTreeMap<NodeId, PathMode>,
}

impl<B: TunnelBackend, S: DataplaneSystem> Phase10Controller<B, S> {
    pub fn new(
        backend: B,
        system: S,
        policy: ContextualPolicySet,
        trust_policy: TrustPolicy,
    ) -> Self {
        Self {
            backend,
            system,
            policy,
            trust_policy,
            state: DataplaneState::Init,
            generation: 0,
            last_safe_generation: 0,
            transitions: Vec::new(),
            selected_exit_node: None,
            lan_access_enabled: false,
            advertised_lan_routes: HashMap::new(),
            lan_route_acl: HashMap::new(),
            peer_paths: BTreeMap::new(),
        }
    }

    pub fn state(&self) -> DataplaneState {
        self.state
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn last_safe_generation(&self) -> u64 {
        self.last_safe_generation
    }

    pub fn transition_audit(&self) -> &[TransitionEvent] {
        &self.transitions
    }

    pub fn selected_exit_node(&self) -> Option<NodeId> {
        self.selected_exit_node.clone()
    }

    pub fn lan_access_enabled(&self) -> bool {
        self.lan_access_enabled
    }

    pub fn establish_control_trust(&mut self, evidence: TrustEvidence) -> Result<(), Phase10Error> {
        validate_trust(&self.trust_policy, evidence)?;
        self.system.check_prerequisites()?;
        self.transition_to(DataplaneState::ControlTrusted, "control_trust_established");
        Ok(())
    }

    pub fn apply_dataplane_generation(
        &mut self,
        evidence: TrustEvidence,
        context: RuntimeContext,
        peers: Vec<PeerConfig>,
        routes: Vec<Route>,
        options: ApplyOptions,
    ) -> Result<(), Phase10Error> {
        validate_trust(&self.trust_policy, evidence)?;
        let target_generation = self.generation.saturating_add(1);
        self.system.set_generation(target_generation);

        if self.state == DataplaneState::Init {
            self.establish_control_trust(evidence)?;
        }
        if !matches!(
            self.state,
            DataplaneState::ControlTrusted
                | DataplaneState::DataplaneApplied
                | DataplaneState::ExitActive
                | DataplaneState::FailClosed
        ) {
            return Err(Phase10Error::InvalidTransition(
                "dataplane apply requires trusted/fail-closed recovery state",
            ));
        }

        self.system.prune_owned_tables()?;

        let mut applied_stages = Vec::new();
        match self.backend.start(context) {
            Ok(()) => applied_stages.push(StageMarker::BackendStarted),
            Err(err) if err.kind == BackendErrorKind::AlreadyRunning => {}
            Err(err) => {
                self.force_fail_closed("backend_start_failed")?;
                return Err(err.into());
            }
        }

        let result = self.apply_generation_stages(peers, routes, options, &mut applied_stages);

        if let Err(err) = result {
            self.rollback_generation(applied_stages)?;
            self.force_fail_closed("apply_failed")?;
            return Err(err);
        }

        self.generation = self.generation.saturating_add(1);
        self.last_safe_generation = self.generation;

        if options.exit_mode == ExitMode::FullTunnel || options.serve_exit_node {
            self.transition_to(
                DataplaneState::ExitActive,
                "dataplane_apply_commit_exit_active",
            );
        } else {
            self.transition_to(DataplaneState::DataplaneApplied, "dataplane_apply_commit");
        }

        Ok(())
    }

    fn apply_generation_stages(
        &mut self,
        peers: Vec<PeerConfig>,
        routes: Vec<Route>,
        options: ApplyOptions,
        applied_stages: &mut Vec<StageMarker>,
    ) -> Result<(), Phase10Error> {
        for peer in &peers {
            self.backend.configure_peer(peer.clone())?;
            self.peer_paths
                .insert(peer.node_id.clone(), PathMode::Direct);
            applied_stages.push(StageMarker::PeerApplied);
        }

        self.system.apply_peer_endpoint_bypass_routes(&peers)?;
        applied_stages.push(StageMarker::EndpointBypassApplied);

        self.backend.apply_routes(routes.clone())?;
        applied_stages.push(StageMarker::BackendRoutesApplied);

        self.system.apply_routes(&routes)?;
        applied_stages.push(StageMarker::SystemRoutesApplied);

        let relay_with_upstream =
            options.exit_mode == ExitMode::FullTunnel && options.serve_exit_node;
        self.system.set_relay_forwarding(relay_with_upstream);
        self.system.apply_firewall_killswitch()?;
        applied_stages.push(StageMarker::FirewallApplied);

        if options.exit_mode == ExitMode::FullTunnel || options.serve_exit_node {
            self.system.apply_nat_forwarding()?;
            applied_stages.push(StageMarker::NatApplied);
        }

        if options.protected_dns {
            self.system.apply_dns_protection()?;
            applied_stages.push(StageMarker::DnsApplied);
        }

        if !options.ipv6_parity_supported {
            self.system.hard_disable_ipv6_egress()?;
            applied_stages.push(StageMarker::Ipv6Blocked);
        }

        self.backend.set_exit_mode(options.exit_mode)?;
        applied_stages.push(StageMarker::ExitModeApplied);

        self.system.assert_killswitch()?;

        Ok(())
    }

    fn rollback_generation(
        &mut self,
        applied_stages: Vec<StageMarker>,
    ) -> Result<(), Phase10Error> {
        for stage in applied_stages.into_iter().rev() {
            match stage {
                StageMarker::ExitModeApplied => {
                    let _ = self.backend.set_exit_mode(ExitMode::Off);
                }
                StageMarker::Ipv6Blocked => {
                    self.system.rollback_ipv6_egress()?;
                }
                StageMarker::DnsApplied => {
                    self.system.rollback_dns_protection()?;
                }
                StageMarker::NatApplied => {
                    self.system.rollback_nat_forwarding()?;
                }
                StageMarker::FirewallApplied => {
                    self.system.rollback_firewall()?;
                }
                StageMarker::EndpointBypassApplied => {
                    self.system.rollback_routes()?;
                }
                StageMarker::SystemRoutesApplied => {
                    self.system.rollback_routes()?;
                }
                StageMarker::BackendRoutesApplied => {
                    self.backend.apply_routes(Vec::new())?;
                }
                StageMarker::PeerApplied => {
                    if let Some(node_id) = self.peer_paths.keys().next().cloned() {
                        self.backend.remove_peer(&node_id)?;
                        self.peer_paths.remove(&node_id);
                    }
                }
                StageMarker::BackendStarted => {
                    let _ = self.backend.shutdown();
                }
            }
        }

        Ok(())
    }

    pub fn force_fail_closed(&mut self, reason: &str) -> Result<(), Phase10Error> {
        self.system.block_all_egress()?;
        self.transition_to(DataplaneState::FailClosed, reason);
        Ok(())
    }

    pub fn set_exit_node(
        &mut self,
        node_id: NodeId,
        requester: &str,
        protocol: Protocol,
    ) -> Result<(), Phase10Error> {
        self.ensure_started()?;

        let decision = self.policy.evaluate(&ContextualAccessRequest {
            src: requester.to_string(),
            dst: format!("node:{}", node_id.as_str()),
            protocol,
            context: TrafficContext::SharedExit,
        });
        if decision != Decision::Allow {
            return Err(Phase10Error::PolicyDenied);
        }

        self.backend.set_exit_mode(ExitMode::FullTunnel)?;
        self.selected_exit_node = Some(node_id);
        self.transition_to(DataplaneState::ExitActive, "exit_node_selected");
        Ok(())
    }

    pub fn clear_exit_node(&mut self) -> Result<(), Phase10Error> {
        self.ensure_started()?;
        self.backend.set_exit_mode(ExitMode::Off)?;
        self.selected_exit_node = None;
        self.transition_to(DataplaneState::DataplaneApplied, "exit_node_cleared");
        Ok(())
    }

    pub fn set_lan_access(&mut self, enabled: bool) {
        self.lan_access_enabled = enabled;
    }

    pub fn advertise_lan_route(&mut self, node_id: NodeId, cidr: &str) {
        self.advertised_lan_routes
            .entry(node_id)
            .or_default()
            .insert(cidr.to_string());
    }

    pub fn set_lan_route_acl(&mut self, user: &str, cidr: &str, allowed: bool) {
        self.lan_route_acl
            .insert((user.to_string(), cidr.to_string()), allowed);
    }

    pub fn ensure_lan_route_allowed(&self, request: RouteGrantRequest) -> Result<(), Phase10Error> {
        if !self.lan_access_enabled {
            return Err(Phase10Error::LanAccessDenied);
        }

        let Some(exit_node) = &self.selected_exit_node else {
            return Err(Phase10Error::ExitNotSelected);
        };

        let advertised = self
            .advertised_lan_routes
            .get(exit_node)
            .map(|routes| routes.contains(&request.cidr))
            .unwrap_or(false);
        if !advertised {
            return Err(Phase10Error::LanAccessDenied);
        }

        let acl_allowed = self
            .lan_route_acl
            .get(&(request.user.clone(), request.cidr.clone()))
            .copied()
            .unwrap_or(false);
        if !acl_allowed {
            return Err(Phase10Error::LanAccessDenied);
        }

        let decision = self.policy.evaluate(&ContextualAccessRequest {
            src: request.user,
            dst: request.cidr,
            protocol: request.protocol,
            context: request.context,
        });
        if decision != Decision::Allow {
            return Err(Phase10Error::PolicyDenied);
        }

        Ok(())
    }

    pub fn mark_direct_failed(&mut self, node_id: &NodeId) -> Result<(), Phase10Error> {
        self.ensure_started()?;
        if let Some(path) = self.peer_paths.get_mut(node_id) {
            *path = PathMode::Relay;
            return Ok(());
        }
        Err(Phase10Error::NotStarted)
    }

    pub fn mark_direct_recovered(&mut self, node_id: &NodeId) -> Result<(), Phase10Error> {
        self.ensure_started()?;
        if let Some(path) = self.peer_paths.get_mut(node_id) {
            *path = PathMode::Direct;
            return Ok(());
        }
        Err(Phase10Error::NotStarted)
    }

    pub fn peer_path(&self, node_id: &NodeId) -> Option<PathMode> {
        self.peer_paths.get(node_id).copied()
    }

    pub fn shutdown(&mut self) -> Result<(), Phase10Error> {
        let _ = self.backend.set_exit_mode(ExitMode::Off);
        self.backend.shutdown()?;
        self.selected_exit_node = None;
        self.lan_access_enabled = false;
        self.transition_to(DataplaneState::Init, "shutdown");
        Ok(())
    }

    fn transition_to(&mut self, target: DataplaneState, reason: &str) {
        let event = TransitionEvent {
            from_state: self.state,
            to_state: target,
            reason: reason.to_string(),
            generation: self.generation,
        };
        self.transitions.push(event);
        self.state = target;
    }

    fn ensure_started(&self) -> Result<(), Phase10Error> {
        if matches!(
            self.state,
            DataplaneState::DataplaneApplied | DataplaneState::ExitActive
        ) {
            return Ok(());
        }
        Err(Phase10Error::NotStarted)
    }
}

fn validate_trust(policy: &TrustPolicy, evidence: TrustEvidence) -> Result<(), Phase10Error> {
    if !evidence.tls13_valid {
        return Err(Phase10Error::TrustRejected("tls13_not_valid"));
    }
    if !evidence.signed_control_valid {
        return Err(Phase10Error::TrustRejected("signed_control_invalid"));
    }
    if evidence.signed_data_age_secs > policy.max_signed_data_age_secs {
        return Err(Phase10Error::TrustRejected("signed_data_stale"));
    }
    if evidence.clock_skew_secs > policy.max_clock_skew_secs {
        return Err(Phase10Error::TrustRejected("clock_skew_exceeded"));
    }
    Ok(())
}

fn resolve_binary_path(
    env_var: &str,
    default: &str,
    program: PrivilegedCommandProgram,
) -> Result<PathBuf, SystemError> {
    let configured = std::env::var(env_var).ok();
    let raw = configured
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default);
    validate_binary_path(raw, program)?;
    Ok(PathBuf::from(raw))
}

fn resolve_binary_path_for_program(
    program: PrivilegedCommandProgram,
) -> Result<PathBuf, SystemError> {
    match program {
        PrivilegedCommandProgram::Ip => resolve_binary_path(
            IP_BINARY_PATH_ENV,
            DEFAULT_IP_BINARY_PATH,
            PrivilegedCommandProgram::Ip,
        ),
        PrivilegedCommandProgram::Nft => resolve_binary_path(
            NFT_BINARY_PATH_ENV,
            DEFAULT_NFT_BINARY_PATH,
            PrivilegedCommandProgram::Nft,
        ),
        PrivilegedCommandProgram::Wg => resolve_binary_path(
            WG_BINARY_PATH_ENV,
            DEFAULT_WG_BINARY_PATH,
            PrivilegedCommandProgram::Wg,
        ),
        PrivilegedCommandProgram::Sysctl => resolve_binary_path(
            SYSCTL_BINARY_PATH_ENV,
            DEFAULT_SYSCTL_BINARY_PATH,
            PrivilegedCommandProgram::Sysctl,
        ),
        PrivilegedCommandProgram::Ifconfig => resolve_binary_path(
            IFCONFIG_BINARY_PATH_ENV,
            DEFAULT_IFCONFIG_BINARY_PATH,
            PrivilegedCommandProgram::Ifconfig,
        ),
        PrivilegedCommandProgram::Route => resolve_binary_path(
            ROUTE_BINARY_PATH_ENV,
            DEFAULT_ROUTE_BINARY_PATH,
            PrivilegedCommandProgram::Route,
        ),
        PrivilegedCommandProgram::Pfctl => resolve_binary_path(
            PFCTL_BINARY_PATH_ENV,
            DEFAULT_PFCTL_BINARY_PATH,
            PrivilegedCommandProgram::Pfctl,
        ),
        PrivilegedCommandProgram::WireguardGo => resolve_binary_path(
            WIREGUARD_GO_BINARY_PATH_ENV,
            DEFAULT_WIREGUARD_GO_BINARY_PATH,
            PrivilegedCommandProgram::WireguardGo,
        ),
        PrivilegedCommandProgram::Kill => resolve_binary_path(
            KILL_BINARY_PATH_ENV,
            DEFAULT_KILL_BINARY_PATH,
            PrivilegedCommandProgram::Kill,
        ),
    }
}

fn validate_binary_path(raw: &str, program: PrivilegedCommandProgram) -> Result<(), SystemError> {
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{} binary path must be absolute: {raw}",
            program.as_str()
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|err| {
        SystemError::PrerequisiteCheckFailed(format!(
            "{} binary canonicalization failed for {}: {err}",
            program.as_str(),
            path.display()
        ))
    })?;
    let metadata = fs::metadata(&canonical).map_err(|err| {
        SystemError::PrerequisiteCheckFailed(format!(
            "{} binary metadata read failed for {}: {err}",
            program.as_str(),
            canonical.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{} binary path must be a regular file: {}",
            program.as_str(),
            canonical.display()
        )));
    }
    #[cfg(unix)]
    {
        let mode = metadata.mode() & 0o777;
        if mode & 0o111 == 0 {
            return Err(SystemError::PrerequisiteCheckFailed(format!(
                "{} binary is not executable: {} ({:03o})",
                program.as_str(),
                canonical.display(),
                mode
            )));
        }
        if mode & 0o022 != 0 {
            return Err(SystemError::PrerequisiteCheckFailed(format!(
                "{} binary must not be group/other writable: {} ({:03o})",
                program.as_str(),
                canonical.display(),
                mode
            )));
        }
        let owner_uid = metadata.uid();
        if owner_uid != 0 {
            return Err(SystemError::PrerequisiteCheckFailed(format!(
                "{} binary must be root-owned: {} (uid={owner_uid})",
                program.as_str(),
                canonical.display()
            )));
        }
    }
    Ok(())
}

fn validate_net_device_name(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 15 {
        return Err("device name length must be between 1 and 15 characters");
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err("device name contains invalid characters");
    }
    Ok(())
}

pub fn write_state_transition_audit(
    path: impl AsRef<Path>,
    transitions: &[TransitionEvent],
) -> Result<(), SystemError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| SystemError::Io(err.to_string()))?;
    }

    let mut output = String::new();
    for transition in transitions {
        output.push_str(&format!(
            "generation={} from={:?} to={:?} reason={}\n",
            transition.generation, transition.from_state, transition.to_state, transition.reason
        ));
    }

    fs::write(path, output).map_err(|err| SystemError::Io(err.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PerfMetric {
    pub name: &'static str,
    pub value: f64,
    pub threshold: &'static str,
    pub status: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Phase10PerfMeasurement {
    pub soak_test_hours: u64,
    pub idle_cpu_percent: f64,
    pub idle_rss_mb: f64,
    pub reconnect_seconds: f64,
    pub route_apply_p95_seconds: f64,
    pub throughput_overhead_percent: f64,
}

impl Phase10PerfMeasurement {
    fn validate(self) -> Result<(), SystemError> {
        if self.soak_test_hours == 0 {
            return Err(SystemError::PrerequisiteCheckFailed(
                "soak_test_hours must be greater than zero".to_string(),
            ));
        }
        for (name, value) in [
            ("idle_cpu_percent", self.idle_cpu_percent),
            ("idle_rss_mb", self.idle_rss_mb),
            ("reconnect_seconds", self.reconnect_seconds),
            ("route_apply_p95_seconds", self.route_apply_p95_seconds),
            (
                "throughput_overhead_percent",
                self.throughput_overhead_percent,
            ),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(SystemError::PrerequisiteCheckFailed(format!(
                    "{name} must be a finite non-negative number"
                )));
            }
        }
        Ok(())
    }
}

fn metric_status(value: f64, threshold_max: f64) -> &'static str {
    if value <= threshold_max {
        "pass"
    } else {
        "fail"
    }
}

pub fn write_phase10_perf_report(
    path: impl AsRef<Path>,
    measurements: Phase10PerfMeasurement,
    environment: &str,
) -> Result<(), SystemError> {
    measurements.validate()?;
    if environment.trim().is_empty() {
        return Err(SystemError::PrerequisiteCheckFailed(
            "environment must not be empty".to_string(),
        ));
    }

    let metrics = [
        PerfMetric {
            name: "idle_cpu_percent",
            value: measurements.idle_cpu_percent,
            threshold: "<=2",
            status: metric_status(measurements.idle_cpu_percent, 2.0),
        },
        PerfMetric {
            name: "idle_rss_mb",
            value: measurements.idle_rss_mb,
            threshold: "<=120",
            status: metric_status(measurements.idle_rss_mb, 120.0),
        },
        PerfMetric {
            name: "reconnect_seconds",
            value: measurements.reconnect_seconds,
            threshold: "<=5",
            status: metric_status(measurements.reconnect_seconds, 5.0),
        },
        PerfMetric {
            name: "route_apply_p95_seconds",
            value: measurements.route_apply_p95_seconds,
            threshold: "<=2",
            status: metric_status(measurements.route_apply_p95_seconds, 2.0),
        },
        PerfMetric {
            name: "throughput_overhead_percent",
            value: measurements.throughput_overhead_percent,
            threshold: "<=15",
            status: metric_status(measurements.throughput_overhead_percent, 15.0),
        },
    ];
    let soak_status = if measurements.soak_test_hours >= 24
        && metrics.iter().all(|metric| metric.status == "pass")
    {
        "pass"
    } else {
        "fail"
    };
    let captured_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| SystemError::Io(err.to_string()))?
        .as_secs();

    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| SystemError::Io(err.to_string()))?;
    }

    let mut out = format!(
        "{{\n  \"phase\": \"phase10\",\n  \"evidence_mode\": \"measured\",\n  \"environment\": \"{}\",\n  \"captured_at_unix\": {},\n  \"soak_test_hours\": {},\n  \"soak_status\": \"{}\",\n  \"metrics\": [\n",
        environment, captured_at_unix, measurements.soak_test_hours, soak_status
    );
    for (index, metric) in metrics.iter().enumerate() {
        let comma = if index + 1 == metrics.len() { "" } else { "," };
        out.push_str(&format!(
            "    {{\"name\":\"{}\",\"value\":{},\"threshold\":\"{}\",\"status\":\"{}\"}}{}\n",
            metric.name, metric.value, metric.threshold, metric.status, comma
        ));
    }
    out.push_str("  ]\n}\n");

    fs::write(path, out).map_err(|err| SystemError::Io(err.to_string()))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use rustynet_backend_api::{
        BackendCapabilities, BackendError, BackendErrorKind, RouteKind, SocketEndpoint, TunnelStats,
    };
    use rustynet_backend_wireguard::WireguardBackend;
    use rustynet_policy::{ContextualPolicyRule, RuleAction};

    use super::*;

    #[derive(Debug, Clone, Copy)]
    enum StartBehavior {
        AlreadyRunning,
        FailInternal,
    }

    #[derive(Debug, Clone, Copy)]
    struct ControlledStartBackend {
        behavior: StartBehavior,
    }

    impl ControlledStartBackend {
        fn new(behavior: StartBehavior) -> Self {
            Self { behavior }
        }
    }

    impl TunnelBackend for ControlledStartBackend {
        fn name(&self) -> &'static str {
            "controlled-start-backend"
        }

        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                supports_roaming: true,
                supports_exit_nodes: true,
                supports_lan_routes: true,
                supports_ipv6: true,
            }
        }

        fn start(&mut self, _context: RuntimeContext) -> Result<(), BackendError> {
            match self.behavior {
                StartBehavior::AlreadyRunning => {
                    Err(BackendError::already_running("backend already running"))
                }
                StartBehavior::FailInternal => Err(BackendError::internal("backend start failed")),
            }
        }

        fn configure_peer(&mut self, _peer: PeerConfig) -> Result<(), BackendError> {
            Ok(())
        }

        fn remove_peer(&mut self, _node_id: &NodeId) -> Result<(), BackendError> {
            Ok(())
        }

        fn apply_routes(&mut self, _routes: Vec<Route>) -> Result<(), BackendError> {
            Ok(())
        }

        fn set_exit_mode(&mut self, _mode: ExitMode) -> Result<(), BackendError> {
            Ok(())
        }

        fn stats(&self) -> Result<TunnelStats, BackendError> {
            Ok(TunnelStats::default())
        }

        fn shutdown(&mut self) -> Result<(), BackendError> {
            Ok(())
        }
    }

    fn allow_shared_exit_policy() -> ContextualPolicySet {
        ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:alice".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::SharedExit],
            }],
        }
    }

    fn trust_ok() -> TrustEvidence {
        TrustEvidence {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 20,
            clock_skew_secs: 10,
        }
    }

    fn sample_peer(id: &str) -> PeerConfig {
        PeerConfig {
            node_id: NodeId::new(id).expect("node id should parse"),
            endpoint: SocketEndpoint {
                addr: "203.0.113.10".parse::<IpAddr>().expect("ip should parse"),
                port: 51820,
            },
            public_key: [9; 32],
            allowed_ips: vec!["100.100.20.2/32".to_string()],
        }
    }

    #[test]
    fn transition_to_fail_closed_when_trust_is_invalid() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let err = controller.establish_control_trust(TrustEvidence {
            tls13_valid: false,
            ..trust_ok()
        });
        assert!(matches!(err, Err(Phase10Error::TrustRejected(_))));
        assert_eq!(controller.state(), DataplaneState::Init);
    }

    #[test]
    fn transactional_apply_commits_generation_and_exit_state() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                RuntimeContext {
                    local_node: NodeId::new("node-a").expect("node should parse"),
                    mesh_cidr: "100.64.0.0/10".to_string(),
                    local_cidr: "100.64.0.1/32".to_string(),
                },
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    ..ApplyOptions::default()
                },
            )
            .expect("apply should succeed");

        assert_eq!(controller.state(), DataplaneState::ExitActive);
        assert_eq!(controller.generation(), 1);
        assert_eq!(controller.last_safe_generation(), 1);
    }

    #[test]
    fn relay_with_upstream_enables_tunnel_forwarding_path() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                RuntimeContext {
                    local_node: NodeId::new("node-a").expect("node should parse"),
                    mesh_cidr: "100.64.0.0/10".to_string(),
                    local_cidr: "100.64.0.1/32".to_string(),
                },
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("relay-with-upstream apply should succeed");

        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "set_relay_forwarding:true")
        );
    }

    #[test]
    fn apply_rejects_backend_start_failure_and_fail_closes() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            ControlledStartBackend::new(StartBehavior::FailInternal),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let result = controller.apply_dataplane_generation(
            trust_ok(),
            RuntimeContext {
                local_node: NodeId::new("node-a").expect("node should parse"),
                mesh_cidr: "100.64.0.0/10".to_string(),
                local_cidr: "100.64.0.1/32".to_string(),
            },
            Vec::new(),
            Vec::new(),
            ApplyOptions::default(),
        );

        let err = result.expect_err("backend start failure must be surfaced");
        assert!(matches!(
            err,
            Phase10Error::Backend(BackendError {
                kind: BackendErrorKind::Internal,
                ..
            })
        ));
        assert_eq!(controller.state(), DataplaneState::FailClosed);
    }

    #[test]
    fn apply_accepts_already_running_backend_start() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            ControlledStartBackend::new(StartBehavior::AlreadyRunning),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                RuntimeContext {
                    local_node: NodeId::new("node-a").expect("node should parse"),
                    mesh_cidr: "100.64.0.0/10".to_string(),
                    local_cidr: "100.64.0.1/32".to_string(),
                },
                Vec::new(),
                Vec::new(),
                ApplyOptions::default(),
            )
            .expect("already-running start should not block reconcile apply");

        assert_eq!(controller.state(), DataplaneState::DataplaneApplied);
        assert_eq!(controller.generation(), 1);
    }

    #[test]
    fn apply_does_not_require_nat_when_not_full_tunnel_or_exit_serving() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default().fail_on("apply_nat_forwarding"),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                RuntimeContext {
                    local_node: NodeId::new("node-a").expect("node should parse"),
                    mesh_cidr: "100.64.0.0/10".to_string(),
                    local_cidr: "100.64.0.1/32".to_string(),
                },
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("nat should not be required for plain mesh apply");

        assert_eq!(controller.state(), DataplaneState::DataplaneApplied);
    }

    #[test]
    fn apply_exit_serving_requires_nat_forwarding() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default().fail_on("apply_nat_forwarding"),
            policy,
            TrustPolicy::default(),
        );

        let result = controller.apply_dataplane_generation(
            trust_ok(),
            RuntimeContext {
                local_node: NodeId::new("node-a").expect("node should parse"),
                mesh_cidr: "100.64.0.0/10".to_string(),
                local_cidr: "100.64.0.1/32".to_string(),
            },
            vec![sample_peer("node-b")],
            vec![Route {
                destination_cidr: "100.100.20.0/24".to_string(),
                via_node: NodeId::new("node-b").expect("node should parse"),
                kind: RouteKind::Mesh,
            }],
            ApplyOptions {
                serve_exit_node: true,
                ..ApplyOptions::default()
            },
        );

        assert!(result.is_err());
        assert_eq!(controller.state(), DataplaneState::FailClosed);
    }

    #[test]
    fn apply_rollback_forces_fail_closed_when_system_step_fails() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default().fail_on("apply_dns_protection"),
            policy,
            TrustPolicy::default(),
        );

        let result = controller.apply_dataplane_generation(
            trust_ok(),
            RuntimeContext {
                local_node: NodeId::new("node-a").expect("node should parse"),
                mesh_cidr: "100.64.0.0/10".to_string(),
                local_cidr: "100.64.0.1/32".to_string(),
            },
            vec![sample_peer("node-b")],
            vec![Route {
                destination_cidr: "0.0.0.0/0".to_string(),
                via_node: NodeId::new("node-b").expect("node should parse"),
                kind: RouteKind::ExitNodeDefault,
            }],
            ApplyOptions {
                protected_dns: true,
                ..ApplyOptions::default()
            },
        );

        assert!(result.is_err());
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert_eq!(controller.last_safe_generation(), 0);
    }

    #[test]
    fn lan_toggle_requires_toggle_route_advertisement_acl_and_policy() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let exit_node = NodeId::new("exit-1").expect("node id should parse");

        controller
            .apply_dataplane_generation(
                trust_ok(),
                RuntimeContext {
                    local_node: NodeId::new("node-a").expect("node should parse"),
                    mesh_cidr: "100.64.0.0/10".to_string(),
                    local_cidr: "100.64.0.1/32".to_string(),
                },
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        controller
            .set_exit_node(exit_node.clone(), "user:alice", Protocol::Tcp)
            .expect("policy should allow selecting exit");

        controller.advertise_lan_route(exit_node, "192.168.1.0/24");
        controller.set_lan_route_acl("user:alice", "192.168.1.0/24", true);

        let denied = controller.ensure_lan_route_allowed(RouteGrantRequest {
            user: "user:alice".to_string(),
            cidr: "192.168.1.0/24".to_string(),
            protocol: Protocol::Tcp,
            context: TrafficContext::SharedExit,
        });
        assert_eq!(denied.err(), Some(Phase10Error::LanAccessDenied));

        controller.set_lan_access(true);
        controller
            .ensure_lan_route_allowed(RouteGrantRequest {
                user: "user:alice".to_string(),
                cidr: "192.168.1.0/24".to_string(),
                protocol: Protocol::Tcp,
                context: TrafficContext::SharedExit,
            })
            .expect("grant should pass with toggle + route + acl + policy");
    }

    #[test]
    fn direct_relay_failover_and_failback_are_recorded() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let peer_id = NodeId::new("node-b").expect("node id should parse");

        controller
            .apply_dataplane_generation(
                trust_ok(),
                RuntimeContext {
                    local_node: NodeId::new("node-a").expect("node should parse"),
                    mesh_cidr: "100.64.0.0/10".to_string(),
                    local_cidr: "100.64.0.1/32".to_string(),
                },
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Direct));

        controller
            .mark_direct_failed(&peer_id)
            .expect("failover should work");
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Relay));

        controller
            .mark_direct_recovered(&peer_id)
            .expect("failback should work");
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Direct));
    }

    #[test]
    fn audit_and_perf_reports_are_writable() {
        let temp_dir = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let audit_path = temp_dir.join(format!(
            "phase10-state-transition-audit-{}-{}.log",
            std::process::id(),
            unique
        ));
        let perf_path = temp_dir.join(format!(
            "phase10-perf-budget-report-{}-{}.json",
            std::process::id(),
            unique
        ));

        write_state_transition_audit(
            &audit_path,
            &[TransitionEvent {
                from_state: DataplaneState::Init,
                to_state: DataplaneState::ControlTrusted,
                reason: "test".to_string(),
                generation: 0,
            }],
        )
        .expect("audit report should be written");
        write_phase10_perf_report(
            &perf_path,
            Phase10PerfMeasurement {
                soak_test_hours: 24,
                idle_cpu_percent: 1.2,
                idle_rss_mb: 82.0,
                reconnect_seconds: 2.0,
                route_apply_p95_seconds: 0.8,
                throughput_overhead_percent: 10.5,
            },
            "unit-test-linux-netns",
        )
        .expect("perf report should be written");

        let audit = std::fs::read_to_string(&audit_path).expect("audit should be readable");
        let perf = std::fs::read_to_string(&perf_path).expect("perf should be readable");
        assert!(audit.contains("generation=0"));
        assert!(perf.contains("idle_cpu_percent"));
        assert!(perf.contains("\"evidence_mode\": \"measured\""));
        assert!(perf.contains("\"captured_at_unix\": "));
        let _ = std::fs::remove_file(&audit_path);
        let _ = std::fs::remove_file(&perf_path);
    }

    #[test]
    fn management_bypass_route_args_use_ipv4_routing_for_ipv4_cidr() {
        let args = LinuxCommandSystem::management_bypass_route_args("192.168.18.0/24", "enp0s8");
        assert_eq!(
            args,
            vec![
                "route".to_string(),
                "replace".to_string(),
                "192.168.18.0/24".to_string(),
                "dev".to_string(),
                "enp0s8".to_string(),
                "table".to_string(),
                "51820".to_string(),
            ]
        );
    }

    #[test]
    fn management_bypass_route_args_use_ipv6_routing_for_ipv6_cidr() {
        let args = LinuxCommandSystem::management_bypass_route_args("fd00::/64", "enp0s8");
        assert_eq!(
            args,
            vec![
                "-6".to_string(),
                "route".to_string(),
                "replace".to_string(),
                "fd00::/64".to_string(),
                "dev".to_string(),
                "enp0s8".to_string(),
                "table".to_string(),
                "51820".to_string(),
            ]
        );
    }

    #[test]
    fn peer_endpoint_bypass_route_args_use_ipv4_host_route() {
        let args = LinuxCommandSystem::peer_endpoint_bypass_route_args(
            "192.168.18.40".parse().expect("valid ipv4"),
            "enp0s8",
        );
        assert_eq!(
            args,
            vec![
                "route".to_string(),
                "replace".to_string(),
                "192.168.18.40/32".to_string(),
                "dev".to_string(),
                "enp0s8".to_string(),
                "table".to_string(),
                "51820".to_string(),
            ]
        );
    }

    #[test]
    fn peer_endpoint_bypass_route_args_use_ipv6_host_route() {
        let args = LinuxCommandSystem::peer_endpoint_bypass_route_args(
            "fd00::10".parse().expect("valid ipv6"),
            "enp0s8",
        );
        assert_eq!(
            args,
            vec![
                "-6".to_string(),
                "route".to_string(),
                "replace".to_string(),
                "fd00::10/128".to_string(),
                "dev".to_string(),
                "enp0s8".to_string(),
                "table".to_string(),
                "51820".to_string(),
            ]
        );
    }

    #[test]
    fn validate_binary_path_rejects_relative_paths() {
        let err = validate_binary_path("ip", PrivilegedCommandProgram::Ip)
            .expect_err("relative paths must be rejected");
        assert!(err.to_string().contains("must be absolute"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_binary_path_rejects_symlink_to_untrusted_target() {
        let temp_dir = std::env::temp_dir().join(format!(
            "phase10-binary-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        let target = temp_dir.join("nft-real");
        let symlink = temp_dir.join("nft-link");
        std::fs::write(&target, "#!/bin/sh\n").expect("target should be writable");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
            .expect("target should be executable");
        std::os::unix::fs::symlink(&target, &symlink).expect("symlink should be creatable");

        let err = validate_binary_path(
            symlink.to_str().expect("symlink path should be utf8"),
            PrivilegedCommandProgram::Nft,
        )
        .expect_err("untrusted symlink targets must be rejected");
        assert!(err.to_string().contains("must be root-owned"));

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn owned_anchor_names_filters_only_rustynet_anchors() {
        let parsed = MacosCommandSystem::owned_anchor_names_from_output(
            "com.apple\ncom.apple/rustynet_g1\ncom.apple/other\n  com.apple/rustynet_g77\n",
        );
        assert_eq!(
            parsed,
            vec![
                "com.apple/rustynet_g1".to_string(),
                "com.apple/rustynet_g77".to_string()
            ]
        );
    }

    #[test]
    fn macos_render_pf_rules_enforces_dns_fail_closed_when_enabled() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.dns_protected = true;
        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");
        assert!(rules.contains("pass out quick inet proto udp on utun9 to any port 53 keep state"));
        assert!(rules.contains("pass out quick inet proto tcp on utun9 to any port 53 keep state"));
        assert!(rules.contains("block drop out quick inet proto udp to any port 53"));
        assert!(rules.contains("block drop out quick inet proto tcp to any port 53"));
    }

    #[test]
    fn macos_render_pf_rules_omits_dns_fail_closed_rules_when_disabled() {
        let system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");
        assert!(!rules.contains("proto udp on utun9 to any port 53"));
        assert!(!rules.contains("proto tcp on utun9 to any port 53"));
        assert!(!rules.contains("block drop out quick inet proto udp to any port 53"));
        assert!(!rules.contains("block drop out quick inet proto tcp to any port 53"));
    }

    #[test]
    fn macos_dns_rule_parser_accepts_port_alias_output() {
        let rules = "pass out quick inet proto udp on utun9 to any port = domain keep state\n\
                     block drop out quick inet proto udp to any port = domain\n";
        assert!(MacosCommandSystem::ruleset_contains_dns_rule(
            rules,
            "pass out quick",
            "udp",
            Some("utun9"),
        ));
        assert!(MacosCommandSystem::ruleset_contains_dns_rule(
            rules,
            "block drop out quick",
            "udp",
            None,
        ));
    }
}
