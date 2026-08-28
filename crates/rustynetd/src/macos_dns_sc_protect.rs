//! macOS System Configuration DNS fail-closed enforcement (M1).
//!
//! Owner-approved mechanism M1 (see
//! `documents/operations/active/MacosDnsFailclosedEnforcementGap_2026-08-28.md`
//! §4): each enabled hardware network service's DNS servers are pointed at the
//! loopback resolver with `networksetup -setdnsservers <service> 127.0.0.1`,
//! so the system resolver's primary nameserver becomes loopback (verifiable
//! via QH-39 `macos-dns-failclosed-check`) instead of advertising the LAN /
//! ISP resolvers while the pf anchor blocks :53.
//!
//! This module owns the PURE half of the mechanism:
//!
//! - argv construction for the four `networksetup` operations the privileged
//!   helper allows (`-listallnetworkservices`, `-getdnsservers`,
//!   `-setdnsservers <svc> 127.0.0.1`, `-setdnsservers <svc> Empty`, and the
//!   exact-list restore form),
//! - service-name validation for values that cross the privileged argv
//!   boundary (host-derived, so treated as untrusted; mirrors
//!   `is_owned_nft_table_token` discipline),
//! - parsing of `-listallnetworkservices` and `-getdnsservers` output,
//! - the session-scoped backup document (which service had which servers
//!   before enforcement) and its save/load round-trip,
//! - the startup-recovery decision function that bounds M1's known crash
//!   risk (SC DNS persists across reboot; a crash without teardown would
//!   otherwise strand host DNS on the dead loopback port).
//!
//! The IMPURE half (actually running the privileged program, sequencing
//! apply/assert/rollback) lives in `phase10.rs`
//! (`MacosCommandSystem::apply_dns_protection` and friends), which keeps the
//! single hardened execution path in one place.
//!
//! Fail-closed posture: every parse/validate function rejects unknown shapes
//! rather than guessing; the backup document records the schema version and
//! refuses to load foreign shapes; the startup decision only ever restores
//! from a readable backup and otherwise demands an explicit operator fix.

use serde::{Deserialize, Serialize};

/// The one fixed binary location the privileged helper allows for
/// `networksetup`. Present on every supported macOS release; there is no
/// fallback path by design (fail closed if it is missing).
pub const NETWORKSETUP_BINARY_PATH: &str = "/usr/sbin/networksetup";

/// Longest service name accepted across the privileged argv boundary.
/// Real macOS service names are far shorter; the bound exists so a hostile
/// inventory cannot push an unbounded token into the helper.
pub const MAX_NETWORKSETUP_SERVICE_NAME_BYTES: usize = 128;

/// Loopback resolver address M1 programs into every enabled service.
pub const LOOPBACK_DNS_SERVER: &str = "127.0.0.1";

/// `networksetup -setdnsservers <service> Empty` is the documented way to
/// clear a service's DNS servers (restore-to-none).
pub const NETWORKSETUP_EMPTY_DNS_KEYWORD: &str = "Empty";

/// Header line `networksetup -listallnetworkservices` prints before the
/// service list. It must never be mistaken for a service name.
pub const NETWORKSETUP_SERVICE_LIST_LEGEND: &str =
    "An asterisk (*) denotes that a network service is currently disabled.";

/// Marker prefix `networksetup` puts on disabled services. Disabled services
/// are out of M1 scope (§5 owner decision: all ENABLED services only).
pub const NETWORKSETUP_DISABLED_SERVICE_PREFIX: char = '*';

/// First line of a `There aren't any DNS Servers set on <service>.` reply —
/// the "no servers configured" outcome of `-getdnsservers`.
pub const NETWORKSETUP_NO_DNS_SERVERS_PREFIX: &str = "There aren't any DNS Servers set on";

/// Validate a network service name before it may cross the privileged argv
/// boundary. Service names are host-derived inventory data, not operator
/// literals, so they are treated as untrusted (§5 owner decision 3, mirroring
/// `is_owned_nft_table_token`): reject empty, overlong, and any name that
/// carries a control character (newline, carriage return, tab, NUL, escape
/// sequences — anything < 0x20 or 0x7f) that could smuggle a second argument
/// or forge helper output.
pub fn is_valid_networksetup_service_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.len() > MAX_NETWORKSETUP_SERVICE_NAME_BYTES {
        return false;
    }
    !name
        .chars()
        .any(|c| c.is_control() || c == char::REPLACEMENT_CHARACTER)
}

/// Validate a literal DNS server list used by the exact-restore argv form.
/// Every entry must be a parseable IP address (the only values
/// `-getdnsservers` can legitimately return) and the list must be non-empty;
/// the empty case is spelled `Empty` instead.
pub fn is_valid_networksetup_dns_server_list(servers: &[&str]) -> bool {
    !servers.is_empty()
        && servers
            .iter()
            .all(|s| s.parse::<std::net::IpAddr>().is_ok())
}

/// argv for enumerating network services (read-only operation).
pub fn networksetup_listall_args() -> [&'static str; 1] {
    ["-listallnetworkservices"]
}

/// argv for reading a service's current DNS servers (read-only operation).
/// Fails the name validator first: no invalid name may reach argv assembly.
pub fn networksetup_getdns_args(service: &str) -> Result<[&str; 2], String> {
    if !is_valid_networksetup_service_name(service) {
        return Err(format!(
            "networksetup service name failed validation: {service:?}"
        ));
    }
    // SAFETY of the lifetime: callers borrow the name for the duration of one
    // privileged run; the returned array cannot outlive `service`.
    Ok(["-getdnsservers", service])
}

/// argv for pointing a service's DNS at the loopback resolver (M1 apply).
pub fn networksetup_setdns_loopback_args(service: &str) -> Result<[&str; 3], String> {
    if !is_valid_networksetup_service_name(service) {
        return Err(format!(
            "networksetup service name failed validation: {service:?}"
        ));
    }
    Ok(["-setdnsservers", service, LOOPBACK_DNS_SERVER])
}

/// argv for clearing a service's DNS servers (restore-to-none; used when the
/// backup recorded that the service had no servers before enforcement).
pub fn networksetup_setdns_empty_args(service: &str) -> Result<[&str; 3], String> {
    if !is_valid_networksetup_service_name(service) {
        return Err(format!(
            "networksetup service name failed validation: {service:?}"
        ));
    }
    Ok(["-setdnsservers", service, NETWORKSETUP_EMPTY_DNS_KEYWORD])
}

/// argv for restoring a service's exact previous DNS server list.
pub fn networksetup_setdns_restore_args<'a>(
    service: &'a str,
    servers: &[&'a str],
) -> Result<Vec<&'a str>, String> {
    if !is_valid_networksetup_service_name(service) {
        return Err(format!(
            "networksetup service name failed validation: {service:?}"
        ));
    }
    if !is_valid_networksetup_dns_server_list(servers) {
        return Err(format!(
            "networksetup restore server list failed validation: {servers:?}"
        ));
    }
    let mut argv = Vec::with_capacity(2 + servers.len());
    argv.push("-setdnsservers");
    argv.push(service);
    argv.extend_from_slice(servers);
    Ok(argv)
}

/// Outcome of parsing `-getdnsservers` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworksetupDnsServers {
    /// The service has no DNS servers configured ("There aren't any…").
    None,
    /// The service's configured servers, in reported order.
    Servers(Vec<String>),
}

/// Parse `-getdnsservers <service>` stdout.
///
/// Fail closed: any line that is neither the documented "none" reply nor a
/// parseable IP address is an error, never silently skipped — a parser that
/// guesses could mistake a localized or future error message for a server
/// list and corrupt the backup.
pub fn parse_networksetup_getdns_output(output: &str) -> Result<NetworksetupDnsServers, String> {
    let mut servers = Vec::new();
    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with(NETWORKSETUP_NO_DNS_SERVERS_PREFIX) {
            // The "none" reply; any additional non-blank line alongside it is
            // an unknown shape and must fail rather than be merged.
            if !servers.is_empty() {
                return Err(format!(
                    "networksetup -getdnsservers output mixed a none-reply with server entries: {output:?}"
                ));
            }
            // Ensure nothing but the none-reply line exists.
            let other_lines = output
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .count();
            if other_lines != 1 {
                return Err(format!(
                    "networksetup -getdnsservers none-reply carried unexpected extra lines: {output:?}"
                ));
            }
            return Ok(NetworksetupDnsServers::None);
        }
        if line.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "networksetup -getdnsservers produced an unparsable entry: {line:?}"
            ));
        }
        servers.push(line.to_owned());
    }
    if servers.is_empty() {
        return Err("networksetup -getdnsservers produced no parsable content".to_owned());
    }
    Ok(NetworksetupDnsServers::Servers(servers))
}

/// Parse `-listallnetworkservices` stdout into the ENABLED service names.
///
/// Layout (observed macOS behavior, §4 M1):
/// - line 1 is the legend ("An asterisk (*) denotes that a network service
///   is currently disabled.") and is skipped,
/// - `*`-prefixed lines are disabled services and are skipped (§5 owner
///   decision 2: M1 scope is all enabled hardware services),
/// - blank lines are skipped,
/// - everything else is an enabled service name.
///
/// Fail closed: a service name that fails argv-boundary validation aborts
/// the whole enumeration (the apply must not partially proceed over a name
/// we could not safely pass to the helper), and an output consisting only of
/// the legend is an error — an macOS host always has at least one service,
/// so an empty list means we parsed something we do not understand.
pub fn parse_networksetup_service_list(output: &str) -> Result<Vec<String>, String> {
    let mut services = Vec::new();
    let mut saw_legend = false;
    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if !saw_legend && line == NETWORKSETUP_SERVICE_LIST_LEGEND {
            saw_legend = true;
            continue;
        }
        if let Some(disabled) = line.strip_prefix(NETWORKSETUP_DISABLED_SERVICE_PREFIX) {
            // The legend may be absent in a future macOS; a disabled entry
            // still confirms this is a service list.
            let _ = disabled;
            continue;
        }
        if !is_valid_networksetup_service_name(line) {
            return Err(format!(
                "networksetup -listallnetworkservices returned a service name that failed validation: {line:?}"
            ));
        }
        services.push(line.to_owned());
    }
    if services.is_empty() {
        return Err(
            "networksetup -listallnetworkservices returned no enabled services (parse failure or unserviceable host)"
                .to_owned(),
        );
    }
    Ok(services)
}

/// True when a `-getdnsservers` result shows exactly the loopback posture M1
/// enforces (non-empty, every entry a loopback address). Used by the assert
/// path to detect drift.
pub fn is_loopback_dns_server_list(servers: &[String]) -> bool {
    !servers.is_empty()
        && servers.iter().all(|s| match s.parse::<std::net::IpAddr>() {
            Ok(ip) => ip.is_loopback(),
            Err(_) => false,
        })
}

/// Session-scoped backup path for the per-service DNS documents M1 captures
/// before enforcement. Same pattern as
/// `RESOLV_CONF_FAILCLOSED_BACKUP_PATH` in `linux_dns_protect.rs`: under the
/// runtime dir on the supported targets, /tmp elsewhere (unit tests run on
/// the non-macos branch on this host's CI).
pub const NETWORKSETUP_DNS_BACKUP_PATH: &str = if cfg!(target_os = "macos") {
    "/private/var/run/rustynet/networksetup-dns.failclosed.bak"
} else if cfg!(target_os = "linux") {
    "/run/rustynet/networksetup-dns.failclosed.bak"
} else {
    "/tmp/rustynet-networksetup-dns.failclosed.bak"
};

/// One service's pre-enforcement DNS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworksetupDnsBackupEntry {
    pub service: String,
    /// `None` = the service had no DNS servers configured (restore with
    /// `Empty`); `Some(list)` = restore the exact list.
    pub servers: Option<Vec<String>>,
}

/// The backup document written before M1 applies loopback DNS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworksetupDnsBackup {
    pub schema_version: u32,
    pub services: Vec<NetworksetupDnsBackupEntry>,
}

pub const NETWORKSETUP_DNS_BACKUP_SCHEMA_VERSION: u32 = 1;

/// Build the backup document from captured per-service state. Empty service
/// sets are rejected: an apply that captured nothing must not write a backup
/// that would silently "restore" nothing later (fail closed).
pub fn build_networksetup_dns_backup(
    entries: Vec<NetworksetupDnsBackupEntry>,
) -> Result<NetworksetupDnsBackup, String> {
    if entries.is_empty() {
        return Err("refusing to build an empty networksetup DNS backup document".to_owned());
    }
    for entry in &entries {
        if !is_valid_networksetup_service_name(&entry.service) {
            return Err(format!(
                "backup entry service name failed validation: {:?}",
                entry.service
            ));
        }
    }
    Ok(NetworksetupDnsBackup {
        schema_version: NETWORKSETUP_DNS_BACKUP_SCHEMA_VERSION,
        services: entries,
    })
}

/// Resolve one service's backup-baseline entry from its freshly captured
/// current DNS (`captured`: `None` = `-getdnsservers` reported no servers).
///
/// This is the M1 capture guard against loopback residue poisoning the
/// restore backup (MacosDnsFailclosedEnforcementGap_2026-08-28 §7): if the
/// captured value is ALREADY the loopback posture M1 itself enforces, it is
/// residue from a prior apply whose teardown never ran (possible when the
/// startup-recovery guard was bypassed because scutil was unreadable).
/// Recording loopback as the baseline would make any later rollback
/// "restore" the strand instead of the operator's real DNS.
///
/// - Normal (non-loopback) captured state, including "no servers", is
///   recorded unchanged — the pre-existing behavior.
/// - Loopback residue WITH a readable prior backup: the prior document's
///   entry for this service is the real pre-enforcement original, so it is
///   preserved instead of overwritten with loopback.
/// - Loopback residue WITHOUT a prior entry for this service: refuse
///   loudly. There is no trustworthy original to fall back to, so the apply
///   aborts and names the manual fix (`networksetup -setdnsservers <service>
///   Empty`, or the operator's real DNS servers) — a silent loopback
///   baseline would be a deferred strand, not a fix.
///
/// A prior backup document that is PRESENT but unreadable never reaches
/// this function: the caller must fail closed on the read error before any
/// baseline is built (an unverifiable document cannot vouch for an
/// original).
pub fn resolve_backup_baseline_entry(
    service: &str,
    captured: Option<Vec<String>>,
    prior_backup: Option<&NetworksetupDnsBackup>,
) -> Result<NetworksetupDnsBackupEntry, String> {
    let captured_is_loopback_residue = captured
        .as_ref()
        .is_some_and(|servers| is_loopback_dns_server_list(servers));
    if !captured_is_loopback_residue {
        return Ok(NetworksetupDnsBackupEntry {
            service: service.to_owned(),
            servers: captured,
        });
    }
    if let Some(prior_entry) = prior_backup.and_then(|backup| {
        backup
            .services
            .iter()
            .find(|entry| entry.service == service)
    }) {
        // The prior document is the only record of this service's real
        // pre-enforcement DNS; keep it rather than overwrite with residue.
        return Ok(prior_entry.clone());
    }
    Err(format!(
        "networksetup DNS backup baseline refused for service {service:?}: its current DNS is the loopback resolver M1 enforces itself, which is residue from a prior apply whose teardown did not run, and no prior backup entry holds the real original. Fix manually before applying DNS protection: sudo {NETWORKSETUP_BINARY_PATH} -setdnsservers {service:?} {NETWORKSETUP_EMPTY_DNS_KEYWORD} (or set the operator's real DNS servers), then retry"
    ))
}

/// Serialize and persist the backup document. Writes are restricted to the
/// owner (0600): the document reveals which resolvers the host used.
pub fn write_networksetup_dns_backup(
    path: &std::path::Path,
    backup: &NetworksetupDnsBackup,
) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("backup dir create failed: {e}"))?;
    }
    let body =
        serde_json::to_vec_pretty(backup).map_err(|e| format!("backup serialize failed: {e}"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("backup write failed: {e}"))?;
    file.write_all(&body)
        .map_err(|e| format!("backup write failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("backup chmod failed: {e}"))?;
    }
    Ok(())
}

/// Load the backup document. Fail closed: a missing file returns `Ok(None)`
/// (the caller decides — the startup guard treats it as the loud-error
/// case), but any PRESENT file that fails to parse, or that carries a
/// foreign schema version or invalid service names, is a hard error rather
/// than a "no backup" answer.
pub fn read_networksetup_dns_backup(
    path: &std::path::Path,
) -> Result<Option<NetworksetupDnsBackup>, String> {
    let body = match std::fs::read(path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("backup read failed: {e}")),
    };
    let backup: NetworksetupDnsBackup = serde_json::from_slice(&body)
        .map_err(|e| format!("backup parse failed (corrupt document): {e}"))?;
    if backup.schema_version != NETWORKSETUP_DNS_BACKUP_SCHEMA_VERSION {
        return Err(format!(
            "backup schema_version {} is not supported (expected {})",
            backup.schema_version, NETWORKSETUP_DNS_BACKUP_SCHEMA_VERSION
        ));
    }
    if backup.services.is_empty() {
        return Err("backup document carries no service entries".to_owned());
    }
    for entry in &backup.services {
        if !is_valid_networksetup_service_name(&entry.service) {
            return Err(format!(
                "backup entry service name failed validation: {:?}",
                entry.service
            ));
        }
    }
    Ok(Some(backup))
}

/// Remove the backup document after a successful restore. A missing file is
/// already-clean, not an error.
pub fn remove_networksetup_dns_backup(path: &std::path::Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("backup removal failed: {e}")),
    }
}

/// What the startup-recovery guard (the approved third piece of M1) decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupRecoveryDecision {
    /// Host SC DNS is not in the fail-closed loopback posture, or protection
    /// is running and owns it — nothing to do.
    NoAction,
    /// Loopback posture present with no protection running and a readable
    /// backup: restore the backup before proceeding.
    RestoreFromBackup,
    /// Loopback posture present, no protection running, and the backup is
    /// missing or unreadable: fail LOUD with an operator-actionable
    /// instruction naming the manual fix per service.
    FailLoudManualRestoreRequired,
}

/// Decide the startup-recovery action (QH-40-shaped, mirror of the shutdown
/// residue startup check).
///
/// Inputs are deliberately plain booleans so the decision itself is pure and
/// unit-testable:
/// - `sc_dns_is_loopback`: the SC posture is the M1 fail-closed posture
///   (primary resolver loopback / services on 127.0.0.1),
/// - `dns_protection_running`: RustyNet DNS protection is currently applied,
/// - `backup_readable`: a valid backup document exists at
///   `NETWORKSETUP_DNS_BACKUP_PATH`.
///
/// The loopback posture itself is M1's durable residue marker: it persists
/// across reboot (unlike pf anchors, which launchd's boot-time `pfctl -F`
/// clears), so a crash between apply and rollback strands host DNS on the
/// dead loopback port. The guard converts that strand into either an
/// automatic restore (backup present) or a loud, actionable refusal
/// (backup lost) — never a silent strand.
pub fn decide_startup_recovery(
    sc_dns_is_loopback: bool,
    dns_protection_running: bool,
    backup_readable: bool,
) -> StartupRecoveryDecision {
    if !sc_dns_is_loopback || dns_protection_running {
        return StartupRecoveryDecision::NoAction;
    }
    if backup_readable {
        StartupRecoveryDecision::RestoreFromBackup
    } else {
        StartupRecoveryDecision::FailLoudManualRestoreRequired
    }
}

/// The operator-actionable message for the backup-lost strand. Names the
/// exact manual fix per affected service (`networksetup -setdnsservers <svc>
/// Empty`) so an operator is never left guessing.
pub fn startup_recovery_manual_restore_message(services: &[String]) -> String {
    let per_service = services
        .iter()
        .map(|s| format!("  sudo {NETWORKSETUP_BINARY_PATH} -setdnsservers {s:?} {NETWORKSETUP_EMPTY_DNS_KEYWORD}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "RustyNet DNS fail-closed residue detected at startup: System Configuration DNS is still loopback but no RustyNet DNS protection is running and the backup document is missing or unreadable ({}). Host DNS resolution will stay broken until the manual fix is applied:\n{per_service}\nThen restart rustynetd.",
        NETWORKSETUP_DNS_BACKUP_PATH
    )
}

/// The operator-actionable startup-recovery guard (the approved third piece
/// of M1). Mirrors the QH-40 shutdown-residue startup check: on daemon start,
/// BEFORE any protection is applied in this process, a loopback SC posture
/// can only be residue from a previous run that crashed before teardown. With
/// a readable backup the guard RESTORES it through the privileged helper; with
/// a missing or corrupt backup it refuses to start, loudly, naming the manual
/// fix — never a silent strand.
///
/// `helper_socket_path` is the daemon's privileged-helper socket (when one is
/// configured); restoring requires it, because `networksetup -setdnsservers`
/// is a privileged operation.
pub fn run_startup_dns_recovery(
    helper_socket_path: Option<&std::path::Path>,
    helper_timeout: std::time::Duration,
) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }
    let sc_dns_is_loopback = match crate::macos_dns_failclosed::read_scutil_dns() {
        Some(body) => crate::macos_dns_failclosed::loopback_resolver_advertised_from_scutil(
            &crate::macos_dns_failclosed::parse_scutil_primary_resolver_nameservers(&body),
        ),
        // scutil unavailable: the fail-closed posture cannot be OBSERVED, so
        // there is no residue evidence — never act on unobservable state.
        None => false,
    };
    let backup = read_networksetup_dns_backup(std::path::Path::new(NETWORKSETUP_DNS_BACKUP_PATH));
    let backup_readable = matches!(backup, Ok(Some(_)));
    match decide_startup_recovery(sc_dns_is_loopback, false, backup_readable) {
        StartupRecoveryDecision::NoAction => Ok(()),
        StartupRecoveryDecision::FailLoudManualRestoreRequired => {
            let services = match &backup {
                Ok(Some(b)) => b
                    .services
                    .iter()
                    .map(|e| e.service.clone())
                    .collect::<Vec<String>>(),
                _ => {
                    // Backup corrupt/absent with unknown service names: still
                    // loud, still actionable — enumerate nothing, name the fix
                    // shape and the backup path.
                    return Err(format!(
                        "RustyNet DNS fail-closed residue detected at startup: System Configuration DNS is loopback, no RustyNet DNS protection is running, and the backup at {} is missing or unreadable. List services with `networksetup -listallnetworkservices` and restore each with:\n  sudo {NETWORKSETUP_BINARY_PATH} -setdnsservers \"<service>\" {NETWORKSETUP_EMPTY_DNS_KEYWORD}\nThen restart rustynetd.",
                        NETWORKSETUP_DNS_BACKUP_PATH
                    ));
                }
            };
            Err(startup_recovery_manual_restore_message(&services))
        }
        StartupRecoveryDecision::RestoreFromBackup => {
            let Some(socket) = helper_socket_path else {
                return Err(format!(
                    "RustyNet DNS fail-closed residue detected at startup: System Configuration DNS is loopback and a backup exists at {}, but no privileged helper socket is configured, so the automatic restore cannot run. Restore manually with `sudo {NETWORKSETUP_BINARY_PATH} -setdnsservers \"<service>\" {NETWORKSETUP_EMPTY_DNS_KEYWORD}` per service, then restart rustynetd.",
                    NETWORKSETUP_DNS_BACKUP_PATH
                ));
            };
            let backup = match backup {
                Ok(Some(backup)) => backup,
                // Locally provable invariant (RestoreFromBackup ⇒ backup
                // readable), but fail closed anyway instead of panicking.
                _ => {
                    return Err(format!(
                        "the networksetup DNS backup at {} became unreadable during startup recovery; restore manually",
                        NETWORKSETUP_DNS_BACKUP_PATH
                    ));
                }
            };
            let client = crate::privileged_helper::PrivilegedCommandClient::new(
                socket.to_path_buf(),
                helper_timeout,
            )?;
            for entry in &backup.services {
                let argv = match &entry.servers {
                    Some(servers) => {
                        let server_refs: Vec<&str> = servers.iter().map(String::as_str).collect();
                        networksetup_setdns_restore_args(&entry.service, &server_refs)?
                    }
                    None => networksetup_setdns_empty_args(&entry.service)?.to_vec(),
                };
                let output = client.run_capture(
                    crate::privileged_helper::PrivilegedCommandProgram::NetworkSetup,
                    &argv,
                )?;
                if !output.success() {
                    return Err(format!(
                        "startup DNS restore for service '{}' failed: status={} stderr={} (manual fix: sudo {NETWORKSETUP_BINARY_PATH} -setdnsservers \"{}\" {NETWORKSETUP_EMPTY_DNS_KEYWORD}; backup retained at {})",
                        entry.service,
                        output.status,
                        output.stderr,
                        entry.service,
                        NETWORKSETUP_DNS_BACKUP_PATH
                    ));
                }
            }
            remove_networksetup_dns_backup(std::path::Path::new(NETWORKSETUP_DNS_BACKUP_PATH))?;
            log::info!(
                "rustynetd startup: restored pre-protection networksetup DNS from backup (M1 startup recovery)"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SERVICE_LIST: &str = "\
An asterisk (*) denotes that a network service is currently disabled.
Wi-Fi
Ethernet
*Bluetooth PAN
Thunderbolt Bridge
";

    #[test]
    fn service_list_parser_skips_legend_disabled_and_blank_lines() {
        let parsed =
            parse_networksetup_service_list(SAMPLE_SERVICE_LIST).expect("sample list must parse");
        assert_eq!(
            parsed,
            vec![
                "Wi-Fi".to_owned(),
                "Ethernet".to_owned(),
                "Thunderbolt Bridge".to_owned()
            ]
        );
    }

    #[test]
    fn service_list_parser_rejects_legend_only_output() {
        let err = parse_networksetup_service_list(NETWORKSETUP_SERVICE_LIST_LEGEND)
            .expect_err("legend-only output must not parse as an empty success");
        assert!(err.contains("no enabled services"));
    }

    #[test]
    fn service_list_parser_rejects_invalid_service_names() {
        // `-listallnetworkservices` output is line-oriented, so a hostile
        // multi-line payload arrives as separate candidate names, each of
        // which is independently validated — no control character can cross
        // the parser. A control character ON a single line must abort the
        // WHOLE enumeration (fail-closed: one bad line ⇒ no service list ⇒
        // the apply fails rather than silently skipping the service).
        let control = format!("{NETWORKSETUP_SERVICE_LIST_LEGEND}\nWi-Fi\nEvil\x1b[1mService\n");
        let err = parse_networksetup_service_list(&control)
            .expect_err("a control character in any service name must abort enumeration");
        assert!(err.contains("failed validation"));
        // A raw LF cannot appear INSIDE a line of the line-oriented protocol
        // (it terminates the line), so it is unrepresentable here by
        // construction; a CR or TAB mid-line IS representable and must abort.
        let carriage_return = format!("{NETWORKSETUP_SERVICE_LIST_LEGEND}\nBad\x0DService\n");
        assert!(parse_networksetup_service_list(&carriage_return).is_err());
        let tab = format!("{NETWORKSETUP_SERVICE_LIST_LEGEND}\nBad\x09Service\n");
        assert!(parse_networksetup_service_list(&tab).is_err());
    }

    #[test]
    fn service_name_validation_rejects_empty_control_and_overlong() {
        assert!(!is_valid_networksetup_service_name(""));
        assert!(!is_valid_networksetup_service_name("Wi-Fi\n"));
        assert!(!is_valid_networksetup_service_name("Wi\n-Fi"));
        assert!(!is_valid_networksetup_service_name("Wi\r\nFi"));
        assert!(!is_valid_networksetup_service_name("tab\tname"));
        assert!(!is_valid_networksetup_service_name("nul\0name"));
        assert!(!is_valid_networksetup_service_name("esc\u{1b}name"));
        let overlong = "x".repeat(MAX_NETWORKSETUP_SERVICE_NAME_BYTES + 1);
        assert!(!is_valid_networksetup_service_name(&overlong));
        assert!(is_valid_networksetup_service_name("Wi-Fi"));
        assert!(is_valid_networksetup_service_name("Thunderbolt Bridge"));
        let max_len = "x".repeat(MAX_NETWORKSETUP_SERVICE_NAME_BYTES);
        assert!(is_valid_networksetup_service_name(&max_len));
    }

    #[test]
    fn argv_builders_cover_enumerate_getdns_loopback_and_empty() {
        assert_eq!(networksetup_listall_args(), ["-listallnetworkservices"]);
        assert_eq!(
            networksetup_getdns_args("Wi-Fi").expect("valid"),
            ["-getdnsservers", "Wi-Fi"]
        );
        assert_eq!(
            networksetup_setdns_loopback_args("Wi-Fi").expect("valid"),
            ["-setdnsservers", "Wi-Fi", "127.0.0.1"]
        );
        assert_eq!(
            networksetup_setdns_empty_args("Wi-Fi").expect("valid"),
            ["-setdnsservers", "Wi-Fi", "Empty"]
        );
        assert!(networksetup_getdns_args("bad\nname").is_err());
        assert!(networksetup_setdns_loopback_args("").is_err());
        assert!(networksetup_setdns_empty_args("tab\tname").is_err());
    }

    #[test]
    fn restore_argv_requires_parseable_non_empty_server_list() {
        let argv = networksetup_setdns_restore_args("Wi-Fi", &["8.8.8.8", "1.1.1.1"])
            .expect("valid restore list");
        assert_eq!(argv, vec!["-setdnsservers", "Wi-Fi", "8.8.8.8", "1.1.1.1"]);
        assert!(networksetup_setdns_restore_args("Wi-Fi", &[]).is_err());
        assert!(networksetup_setdns_restore_args("Wi-Fi", &["not-an-ip"]).is_err());
        assert!(networksetup_setdns_restore_args("bad\nname", &["8.8.8.8"]).is_err());
    }

    #[test]
    fn getdns_parser_distinguishes_none_reply_from_server_lists() {
        assert_eq!(
            parse_networksetup_getdns_output("There aren't any DNS Servers set on Wi-Fi.\n")
                .expect("none reply"),
            NetworksetupDnsServers::None
        );
        assert_eq!(
            parse_networksetup_getdns_output("8.8.8.8\n1.1.1.1\n").expect("server list"),
            NetworksetupDnsServers::Servers(vec!["8.8.8.8".to_owned(), "1.1.1.1".to_owned()])
        );
        assert!(parse_networksetup_getdns_output("").is_err());
        assert!(parse_networksetup_getdns_output("some error text\n").is_err());
        assert!(parse_networksetup_getdns_output("8.8.8.8\nnot-an-ip\n").is_err());
        assert!(
            parse_networksetup_getdns_output(
                "There aren't any DNS Servers set on Wi-Fi.\n8.8.8.8\n"
            )
            .is_err(),
            "none-reply mixed with entries must fail closed"
        );
    }

    #[test]
    fn loopback_server_list_detection() {
        assert!(is_loopback_dns_server_list(&["127.0.0.1".to_owned()]));
        assert!(is_loopback_dns_server_list(&["::1".to_owned()]));
        assert!(!is_loopback_dns_server_list(&[]));
        assert!(!is_loopback_dns_server_list(&["8.8.8.8".to_owned()]));
        assert!(!is_loopback_dns_server_list(&[
            "127.0.0.1".to_owned(),
            "8.8.8.8".to_owned()
        ]));
        assert!(!is_loopback_dns_server_list(&["garbage".to_owned()]));
    }

    #[test]
    fn backup_round_trip_preserves_entries_and_none_state() {
        let backup = build_networksetup_dns_backup(vec![
            NetworksetupDnsBackupEntry {
                service: "Wi-Fi".to_owned(),
                servers: Some(vec!["8.8.8.8".to_owned(), "1.1.1.1".to_owned()]),
            },
            NetworksetupDnsBackupEntry {
                service: "Ethernet".to_owned(),
                servers: None,
            },
        ])
        .expect("valid backup");
        let dir = std::env::temp_dir().join(format!("rustynet-sc-dns-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("backup.json");
        write_networksetup_dns_backup(&path, &backup).expect("write");
        let loaded = read_networksetup_dns_backup(&path)
            .expect("read")
            .expect("document present");
        assert_eq!(loaded, backup);
        assert!(remove_networksetup_dns_backup(&path).is_ok());
        assert!(
            read_networksetup_dns_backup(&path)
                .expect("missing file is Ok(None)")
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_reader_rejects_foreign_shapes_and_invalid_names() {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-sc-dns-test-reject-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("corrupt.json");
        std::fs::write(&path, b"{ not json").expect("write");
        assert!(read_networksetup_dns_backup(&path).is_err());

        let foreign =
            r#"{"schema_version": 99, "services": [{"service": "Wi-Fi", "servers": null}]}"#;
        std::fs::write(&path, foreign).expect("write");
        assert!(read_networksetup_dns_backup(&path).is_err());

        let hostile =
            "{\"schema_version\": 1, \"services\": [{\"service\": \"bad\\nname\", \"servers\": null}]}";
        std::fs::write(&path, hostile).expect("write");
        assert!(read_networksetup_dns_backup(&path).is_err());

        let empty = "{\"schema_version\": 1, \"services\": []}";
        std::fs::write(&path, empty).expect("write");
        assert!(read_networksetup_dns_backup(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_backup_document_is_refused() {
        assert!(build_networksetup_dns_backup(Vec::new()).is_err());
    }

    #[test]
    fn backup_baseline_refuses_loopback_residue_without_prior_original() {
        // Loopback residue and NO prior backup at all: refuse loudly, naming
        // the service and the manual fix — a silent loopback baseline would
        // defer the strand to rollback time.
        let err = resolve_backup_baseline_entry("Wi-Fi", Some(vec!["127.0.0.1".to_owned()]), None)
            .expect_err("loopback residue with no prior backup must refuse");
        assert!(err.contains("Wi-Fi"));
        assert!(err.contains("-setdnsservers"));
        assert!(err.contains("Empty"));
        // Residue with a prior backup that does not cover THIS service is the
        // same no-trustworthy-original case.
        let prior = build_networksetup_dns_backup(vec![NetworksetupDnsBackupEntry {
            service: "Ethernet".to_owned(),
            servers: Some(vec!["8.8.8.8".to_owned()]),
        }])
        .expect("valid prior backup");
        assert!(
            resolve_backup_baseline_entry("Wi-Fi", Some(vec!["::1".to_owned()]), Some(&prior))
                .is_err()
        );
    }

    #[test]
    fn backup_baseline_preserves_prior_original_over_loopback_residue() {
        // Loopback residue with a readable prior backup: the prior document's
        // entry is the real pre-enforcement original and must be preserved,
        // never overwritten with loopback.
        let prior = build_networksetup_dns_backup(vec![
            NetworksetupDnsBackupEntry {
                service: "Wi-Fi".to_owned(),
                servers: Some(vec!["8.8.8.8".to_owned(), "1.1.1.1".to_owned()]),
            },
            NetworksetupDnsBackupEntry {
                service: "Ethernet".to_owned(),
                servers: None,
            },
        ])
        .expect("valid prior backup");
        let resolved = resolve_backup_baseline_entry(
            "Wi-Fi",
            Some(vec!["127.0.0.1".to_owned()]),
            Some(&prior),
        )
        .expect("prior original must be preserved");
        assert_eq!(resolved.service, "Wi-Fi");
        assert_eq!(
            resolved.servers,
            Some(vec!["8.8.8.8".to_owned(), "1.1.1.1".to_owned()])
        );
        // The None (no servers configured) original is preserved as None too.
        let resolved_none = resolve_backup_baseline_entry(
            "Ethernet",
            Some(vec!["127.0.0.1".to_owned()]),
            Some(&prior),
        )
        .expect("prior None original must be preserved");
        assert_eq!(resolved_none.servers, None);
    }

    #[test]
    fn backup_baseline_records_normal_captured_dns_unchanged() {
        // Normal non-loopback current values (and the no-servers case) are
        // recorded exactly as captured — the pre-existing behavior.
        let resolved =
            resolve_backup_baseline_entry("Wi-Fi", Some(vec!["8.8.8.8".to_owned()]), None)
                .expect("normal capture must record");
        assert_eq!(resolved.servers, Some(vec!["8.8.8.8".to_owned()]));
        let resolved_none = resolve_backup_baseline_entry("Ethernet", None, None)
            .expect("no-servers capture must record");
        assert_eq!(resolved_none.servers, None);
        // A mixed list containing one non-loopback entry is NOT pure loopback
        // posture, so it is captured as-is (the apply is about to overwrite
        // it wholesale with loopback anyway).
        let resolved_mixed = resolve_backup_baseline_entry(
            "Thunderbolt Bridge",
            Some(vec!["127.0.0.1".to_owned(), "8.8.8.8".to_owned()]),
            None,
        )
        .expect("mixed capture must record");
        assert_eq!(
            resolved_mixed.servers,
            Some(vec!["127.0.0.1".to_owned(), "8.8.8.8".to_owned()])
        );
    }

    #[test]
    fn startup_guard_restores_from_readable_backup_only() {
        // Not in loopback posture: no action regardless.
        assert_eq!(
            decide_startup_recovery(false, false, false),
            StartupRecoveryDecision::NoAction
        );
        // Loopback posture but protection is running and owns it.
        assert_eq!(
            decide_startup_recovery(true, true, false),
            StartupRecoveryDecision::NoAction
        );
        // The strand case with a backup: restore.
        assert_eq!(
            decide_startup_recovery(true, false, true),
            StartupRecoveryDecision::RestoreFromBackup
        );
        // The strand case without a backup: fail loud.
        assert_eq!(
            decide_startup_recovery(true, false, false),
            StartupRecoveryDecision::FailLoudManualRestoreRequired
        );
    }

    #[test]
    fn manual_restore_message_names_the_fix_per_service() {
        let message =
            startup_recovery_manual_restore_message(&["Wi-Fi".to_owned(), "Ethernet".to_owned()]);
        assert!(message.contains("networksetup-dns.failclosed.bak"));
        assert!(message.contains("-setdnsservers \"Wi-Fi\" Empty"));
        assert!(message.contains("-setdnsservers \"Ethernet\" Empty"));
        assert!(message.contains("/usr/sbin/networksetup"));
    }
}
