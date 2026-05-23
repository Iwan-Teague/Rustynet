#![allow(clippy::result_large_err)]

//! Windows exit-mode NAT lifecycle artefact producer.
//!
//! Emits a single-phase snapshot for the Windows Exit NAT lifecycle
//! proof. The orchestrator captures one snapshot during exit mode and
//! one after service stop, then merges both with
//! [`merge_windows_exit_nat_lifecycle_artifact`] into the validator's
//! `scm_context_nat_lifecycle.json` shape.

use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(windows)]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const WINDOWS_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_WINDOWS_EXIT_NAT_NAME: &str = "RustyNetExit-rustynet0";
pub const DEFAULT_WINDOWS_TUNNEL_ALIAS: &str = "rustynet0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsExitNatLifecycleOptions {
    pub mesh_cidr: String,
    pub nat_name: String,
    pub tunnel_alias: String,
}

impl Default for WindowsExitNatLifecycleOptions {
    fn default() -> Self {
        Self {
            mesh_cidr: String::new(),
            nat_name: DEFAULT_WINDOWS_EXIT_NAT_NAME.to_owned(),
            tunnel_alias: DEFAULT_WINDOWS_TUNNEL_ALIAS.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsExitNatLifecycleSnapshot {
    pub schema_version: u32,
    pub captured_at_unix: i64,
    pub mesh_cidr: String,
    pub nat_name: String,
    pub tunnel_alias: String,
    pub egress_alias: String,
    pub netnat_present: bool,
    pub internal_prefix: String,
    pub tunnel_forwarding: String,
    pub egress_forwarding: String,
    pub portproxy_summary: String,
}

pub fn collect_windows_exit_nat_lifecycle_snapshot(
    options: &WindowsExitNatLifecycleOptions,
) -> Result<WindowsExitNatLifecycleSnapshot, String> {
    validate_windows_nat_options(options)?;
    let now = current_unix_seconds();
    let netnat_json = capture_windows_netnat_json(options.nat_name.as_str()).unwrap_or_default();
    let (netnat_present, internal_prefix) = parse_netnat_json(netnat_json.as_str());
    let egress_alias = capture_windows_default_egress_alias(options.tunnel_alias.as_str())
        .unwrap_or_default()
        .trim()
        .to_owned();
    let tunnel_forwarding = capture_windows_forwarding_state(options.tunnel_alias.as_str())
        .unwrap_or_else(|err| format!("Error: {err}"));
    let egress_forwarding = if egress_alias.is_empty() {
        "Error: no non-tunnel default egress interface detected".to_owned()
    } else {
        capture_windows_forwarding_state(egress_alias.as_str())
            .unwrap_or_else(|err| format!("Error: {err}"))
    };
    let portproxy_summary = capture_windows_portproxy_summary().unwrap_or_default();
    Ok(WindowsExitNatLifecycleSnapshot {
        schema_version: WINDOWS_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION,
        captured_at_unix: now,
        mesh_cidr: options.mesh_cidr.clone(),
        nat_name: options.nat_name.clone(),
        tunnel_alias: options.tunnel_alias.clone(),
        egress_alias,
        netnat_present,
        internal_prefix,
        tunnel_forwarding,
        egress_forwarding,
        portproxy_summary,
    })
}

pub fn build_windows_exit_nat_lifecycle_snapshot(
    captured_at_unix: i64,
    options: &WindowsExitNatLifecycleOptions,
    netnat_json: &str,
    tunnel_forwarding: &str,
    egress_forwarding: &str,
    egress_alias: &str,
    portproxy_summary: &str,
) -> Result<WindowsExitNatLifecycleSnapshot, String> {
    validate_windows_nat_options(options)?;
    let (netnat_present, internal_prefix) = parse_netnat_json(netnat_json);
    Ok(WindowsExitNatLifecycleSnapshot {
        schema_version: WINDOWS_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION,
        captured_at_unix,
        mesh_cidr: options.mesh_cidr.clone(),
        nat_name: options.nat_name.clone(),
        tunnel_alias: options.tunnel_alias.clone(),
        egress_alias: egress_alias.trim().to_owned(),
        netnat_present,
        internal_prefix,
        tunnel_forwarding: normalize_forwarding_state(tunnel_forwarding),
        egress_forwarding: normalize_forwarding_state(egress_forwarding),
        portproxy_summary: portproxy_summary.to_owned(),
    })
}

pub fn merge_windows_exit_nat_lifecycle_artifact(
    during_run: &WindowsExitNatLifecycleSnapshot,
    after_stop: &WindowsExitNatLifecycleSnapshot,
) -> serde_json::Value {
    let forwarding_restored = !after_stop.netnat_present
        && !after_stop.tunnel_forwarding.eq_ignore_ascii_case("Enabled")
        && !after_stop.egress_forwarding.eq_ignore_ascii_case("Enabled");
    serde_json::json!({
        "schema_version": WINDOWS_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION,
        "nat_name": during_run.nat_name,
        "mesh_cidr": during_run.mesh_cidr,
        "during_run": {
            "netnat_present": during_run.netnat_present,
            "internal_prefix": during_run.internal_prefix,
            "tunnel_forwarding": during_run.tunnel_forwarding,
            "egress_forwarding": during_run.egress_forwarding,
            "egress_alias": during_run.egress_alias,
        },
        "after_stop": {
            "netnat_present": after_stop.netnat_present,
            "forwarding_restored": forwarding_restored,
            "tunnel_forwarding": after_stop.tunnel_forwarding,
            "egress_forwarding": after_stop.egress_forwarding,
        },
    })
}

pub fn validate_windows_nat_options(
    options: &WindowsExitNatLifecycleOptions,
) -> Result<(), String> {
    validate_ipv4_cidr_like(options.mesh_cidr.as_str(), "mesh CIDR")?;
    validate_windows_safe_name(options.nat_name.as_str(), "NAT name")?;
    validate_windows_safe_name(options.tunnel_alias.as_str(), "tunnel alias")?;
    Ok(())
}

pub fn parse_netnat_json(raw: &str) -> (bool, String) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (false, String::new());
    }
    let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
        return (false, String::new());
    };
    let selected = value
        .as_array()
        .and_then(|values| values.first())
        .unwrap_or(&value);
    let prefix = selected
        .get("InternalIPInterfaceAddressPrefix")
        .or_else(|| selected.get("internal_prefix"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    (!prefix.is_empty(), prefix)
}

fn normalize_forwarding_state(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("enabled") {
        "Enabled".to_owned()
    } else if trimmed.eq_ignore_ascii_case("disabled") {
        "Disabled".to_owned()
    } else if trimmed.is_empty() {
        "Error: empty forwarding state".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn validate_windows_safe_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!("{label} contains unsupported characters"));
    }
    Ok(())
}

fn validate_ipv4_cidr_like(value: &str, label: &str) -> Result<(), String> {
    let Some((addr, prefix)) = value.split_once('/') else {
        return Err(format!("{label} must be CIDR-like"));
    };
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| format!("{label} prefix must be numeric"))?;
    if prefix > 32 {
        return Err(format!("{label} prefix must be <= 32"));
    }
    let octets = addr.split('.').collect::<Vec<_>>();
    if octets.len() != 4
        || octets
            .iter()
            .any(|octet| octet.is_empty() || octet.parse::<u8>().is_err())
    {
        return Err(format!("{label} must be IPv4 CIDR-like"));
    }
    Ok(())
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(windows)]
fn capture_windows_netnat_json(nat_name: &str) -> Result<String, String> {
    run_powershell_with_args(
        r#"param([string]$Name)
$nat = Get-NetNat -Name $Name -ErrorAction SilentlyContinue
if ($null -eq $nat) { exit 0 }
$nat | Select-Object Name,InternalIPInterfaceAddressPrefix | ConvertTo-Json -Compress
"#,
        &[nat_name],
    )
}

#[cfg(not(windows))]
fn capture_windows_netnat_json(_nat_name: &str) -> Result<String, String> {
    Ok(String::new())
}

#[cfg(windows)]
fn capture_windows_forwarding_state(alias: &str) -> Result<String, String> {
    run_powershell_with_args(
        r#"param([string]$Alias)
[string]((Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction Stop).Forwarding)
"#,
        &[alias],
    )
    .map(|value| normalize_forwarding_state(value.as_str()))
}

#[cfg(not(windows))]
fn capture_windows_forwarding_state(_alias: &str) -> Result<String, String> {
    Ok("Disabled".to_owned())
}

#[cfg(windows)]
fn capture_windows_default_egress_alias(tunnel_alias: &str) -> Result<String, String> {
    run_powershell_with_args(
        r#"param([string]$TunnelAlias)
[string](Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
  Where-Object { $_.InterfaceAlias -ne $TunnelAlias } |
  Sort-Object -Property RouteMetric,InterfaceMetric |
  Select-Object -First 1 -ExpandProperty InterfaceAlias)
"#,
        &[tunnel_alias],
    )
}

#[cfg(not(windows))]
fn capture_windows_default_egress_alias(_tunnel_alias: &str) -> Result<String, String> {
    Ok(String::new())
}

#[cfg(windows)]
fn capture_windows_portproxy_summary() -> Result<String, String> {
    let output = Command::new("netsh")
        .args(["interface", "portproxy", "show", "all"])
        .output()
        .map_err(|err| format!("netsh interface portproxy show all failed to start: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "netsh interface portproxy show all failed: status={} stderr={}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(windows))]
fn capture_windows_portproxy_summary() -> Result<String, String> {
    Ok(String::new())
}

#[cfg(windows)]
fn run_powershell_with_args(script: &str, values: &[&str]) -> Result<String, String> {
    let mut command = Command::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]);
    command.args(values);
    let output = command
        .output()
        .map_err(|err| format!("PowerShell capture failed to start: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "PowerShell capture failed: status={} stderr={}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> WindowsExitNatLifecycleOptions {
        WindowsExitNatLifecycleOptions {
            mesh_cidr: "100.64.0.0/10".to_owned(),
            nat_name: DEFAULT_WINDOWS_EXIT_NAT_NAME.to_owned(),
            tunnel_alias: DEFAULT_WINDOWS_TUNNEL_ALIAS.to_owned(),
        }
    }

    #[test]
    fn netnat_parser_accepts_powershell_json() {
        let (present, prefix) = parse_netnat_json(
            r#"{"Name":"RustyNetExit-rustynet0","InternalIPInterfaceAddressPrefix":"100.64.0.0/10"}"#,
        );
        assert!(present);
        assert_eq!(prefix, "100.64.0.0/10");
    }

    #[test]
    fn netnat_parser_fails_closed_on_empty_or_invalid_json() {
        assert_eq!(parse_netnat_json(""), (false, String::new()));
        assert_eq!(parse_netnat_json("not-json"), (false, String::new()));
    }

    #[test]
    fn snapshot_builder_normalizes_forwarding_fields() {
        let snap = build_windows_exit_nat_lifecycle_snapshot(
            7,
            &options(),
            r#"{"InternalIPInterfaceAddressPrefix":"100.64.0.0/10"}"#,
            "enabled\n",
            "Disabled",
            "Ethernet",
            "",
        )
        .expect("snapshot must build");
        assert!(snap.netnat_present);
        assert_eq!(snap.tunnel_forwarding, "Enabled");
        assert_eq!(snap.egress_forwarding, "Disabled");
    }

    #[test]
    fn merge_helper_matches_validator_shape() {
        let during = build_windows_exit_nat_lifecycle_snapshot(
            1,
            &options(),
            r#"{"InternalIPInterfaceAddressPrefix":"100.64.0.0/10"}"#,
            "Enabled",
            "Enabled",
            "Ethernet",
            "Listen on ipv4: connect to ipv4:",
        )
        .unwrap();
        let after = build_windows_exit_nat_lifecycle_snapshot(
            2,
            &options(),
            "",
            "Disabled",
            "Disabled",
            "Ethernet",
            "",
        )
        .unwrap();
        let merged = merge_windows_exit_nat_lifecycle_artifact(&during, &after);
        assert_eq!(merged["schema_version"], 1);
        assert_eq!(merged["mesh_cidr"], "100.64.0.0/10");
        assert_eq!(merged["nat_name"], DEFAULT_WINDOWS_EXIT_NAT_NAME);
        assert_eq!(merged["during_run"]["netnat_present"], true);
        assert_eq!(merged["after_stop"]["forwarding_restored"], true);
    }

    #[test]
    fn validation_rejects_shell_metacharacters() {
        let mut opts = options();
        opts.nat_name = "RustyNet;Remove-Item".to_owned();
        assert!(validate_windows_nat_options(&opts).is_err());
    }
}
