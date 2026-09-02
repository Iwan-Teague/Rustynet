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
//!   otherwise strand host DNS on the dead loopback port), widened by S4
//!   with a per-service DNS observation (scutil primary OR any enabled
//!   service pinned loopback-only; degrade-with-loud-warning when the
//!   helper is unobservable),
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

/// Invariant substring shared by every observed wording of the
/// `-listallnetworkservices` legend. macOS hosts in the field have shipped
/// the shorter variant "An asterisk (*) denotes that a network service is
/// disabled." (no "currently"), so the parser matches on this substring
/// instead of the full sentence — an exact-match skip silently turned the
/// variant legend into a phantom service name and failed every later
/// `networksetup` call against it. No real service name contains this
/// phrase (it names the tool's own convention), so the match is unambiguous.
pub const NETWORKSETUP_SERVICE_LIST_LEGEND_MARKER: &str =
    "asterisk (*) denotes that a network service is";

/// True when a `-listallnetworkservices` output line is the disclaimer
/// legend (any observed wording variant). Such lines are structural output,
/// never service names.
pub fn is_networksetup_service_list_legend(line: &str) -> bool {
    line.contains(NETWORKSETUP_SERVICE_LIST_LEGEND_MARKER)
}

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
/// - the legend line ("An asterisk (*) denotes that a network service is
///   [currently] disabled.", matched by wording-invariant substring) is
///   skipped,
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
    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if is_networksetup_service_list_legend(line) {
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
/// - `residue_evidence`: the SC posture carries M1's durable residue marker
///   (S4-widened meaning: the scutil primary resolver advertises loopback OR
///   any enabled service observes a loopback-only pin — see
///   `residue_evidence_from_observation`; the signature and truth table are
///   unchanged, only the meaning of this first argument widened),
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
    residue_evidence: bool,
    dns_protection_running: bool,
    backup_readable: bool,
) -> StartupRecoveryDecision {
    if !residue_evidence || dns_protection_running {
        return StartupRecoveryDecision::NoAction;
    }
    if backup_readable {
        StartupRecoveryDecision::RestoreFromBackup
    } else {
        StartupRecoveryDecision::FailLoudManualRestoreRequired
    }
}

/// Per-service DNS posture classification for the startup guard's per-service
/// observation (S4). One enabled service's `-getdnsservers` state, classified
/// against the M1 pin posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceDnsPosture {
    /// The service has no DNS servers configured.
    None,
    /// Every configured server is a loopback address — the exact posture M1
    /// pins, so outside a running protection this is residue.
    LoopbackOnly,
    /// At least one configured server is not loopback.
    NonLoopback,
}

/// Outcome of the startup guard's per-service DNS observation (S4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceDnsObservation {
    /// Enumeration and every per-service read completed; carries the
    /// classification per enabled service.
    Observed(Vec<(String, ServiceDnsPosture)>),
    /// The helper socket is absent, or a round trip failed, or an output had
    /// an unparsable shape: the per-service posture is unobservable this
    /// startup. The guard degrades (scutil-only signal) with a loud warning
    /// rather than refusing startup — refusal is reserved for
    /// confirmed-residue + unrecoverable (design §3.2(4)).
    ObservationUnavailable(String),
}

/// Classify one service's `-getdnsservers` output (S4). Reuses the module's
/// existing parser and loopback detector; any unparsable shape is an error,
/// never a guess (fail closed at the observation layer — the caller degrades).
pub fn classify_getdns_output(output: &str) -> Result<ServiceDnsPosture, String> {
    match parse_networksetup_getdns_output(output)? {
        NetworksetupDnsServers::None => Ok(ServiceDnsPosture::None),
        NetworksetupDnsServers::Servers(servers) => {
            if is_loopback_dns_server_list(&servers) {
                Ok(ServiceDnsPosture::LoopbackOnly)
            } else {
                Ok(ServiceDnsPosture::NonLoopback)
            }
        }
    }
}

/// Aggregate the S4-widened residue-evidence bit from the scutil primary
/// signal and the per-service observation. Degradation is built in: when the
/// observation is unavailable the scutil-only signal (the pre-S4 behavior)
/// is used, so an unobservable posture can never manufacture residue
/// evidence — but neither can it hide the scutil half.
pub fn residue_evidence_from_observation(
    sc_dns_is_loopback: bool,
    observation: &ServiceDnsObservation,
) -> bool {
    match observation {
        ServiceDnsObservation::Observed(postures) => {
            sc_dns_is_loopback
                || postures
                    .iter()
                    .any(|(_, posture)| *posture == ServiceDnsPosture::LoopbackOnly)
        }
        ServiceDnsObservation::ObservationUnavailable(_) => sc_dns_is_loopback,
    }
}

/// The still-loopback-pinned service names from a completed per-service
/// observation (S4-A2). Empty for an `ObservationUnavailable` — callers
/// tri-state on the observation itself; an unavailable observation never
/// manufactures a survivor list.
fn surviving_loopback_services(observation: &ServiceDnsObservation) -> Vec<String> {
    match observation {
        ServiceDnsObservation::Observed(postures) => postures
            .iter()
            .filter(|(_, posture)| *posture == ServiceDnsPosture::LoopbackOnly)
            .map(|(service, _)| service.clone())
            .collect(),
        ServiceDnsObservation::ObservationUnavailable(_) => Vec::new(),
    }
}

/// The loud startup warning emitted when per-service observation degrades:
/// names the blind spot so a degraded startup is never silent.
pub fn observation_unavailable_warning(reason: &str) -> String {
    format!(
        "RustyNet DNS fail-closed startup guard: per-service DNS observation unavailable ({reason}); partial SC loopback residue may be missed until the first apply. Proceeding with the scutil primary-resolver signal only."
    )
}

/// The concrete service list the loud refusal names (S4): the observed
/// loopback-pinned services first, then the backup's recorded entries as a
/// fallback, deduplicated in order. With per-service observation there is
/// always a concrete list to name; an empty result means neither source
/// yielded a name and the caller falls back to the backup-shape hint.
fn fail_loud_service_list(
    observation: &ServiceDnsObservation,
    backup: &Result<Option<NetworksetupDnsBackup>, String>,
) -> Vec<String> {
    let mut services = Vec::new();
    if let ServiceDnsObservation::Observed(postures) = observation {
        for (service, posture) in postures {
            if *posture == ServiceDnsPosture::LoopbackOnly && !services.contains(service) {
                services.push(service.clone());
            }
        }
    }
    if let Ok(Some(backup)) = backup {
        for entry in &backup.services {
            if !services.contains(&entry.service) {
                services.push(entry.service.clone());
            }
        }
    }
    services
}

/// The exact per-entry argv the startup restore loop issues (pure so the
/// widened guard's restore behavior is pinned by unit test): a recorded
/// server list restores exactly, a recorded no-servers state restores with
/// `Empty`.
fn startup_restore_argv_for_entry(
    entry: &NetworksetupDnsBackupEntry,
) -> Result<Vec<String>, String> {
    match &entry.servers {
        Some(servers) => {
            let server_refs: Vec<&str> = servers.iter().map(String::as_str).collect();
            networksetup_setdns_restore_args(&entry.service, &server_refs)
                .map(|argv| argv.into_iter().map(str::to_owned).collect())
        }
        None => networksetup_setdns_empty_args(&entry.service)
            .map(|argv| argv.into_iter().map(str::to_owned).collect()),
    }
}

/// Observe every enabled service's DNS posture through the privileged helper
/// (S4). Fails by degrading: any construction/round-trip/parse failure
/// returns `ObservationUnavailable` naming the reason, never a guess. This
/// is the impure wiring; the round-trip shape itself is
/// `observe_service_dns_postures_with` (unit-tested over faked round trips).
pub fn observe_service_dns_postures(
    helper_socket_path: Option<&std::path::Path>,
    helper_timeout: std::time::Duration,
) -> ServiceDnsObservation {
    let Some(socket) = helper_socket_path else {
        return ServiceDnsObservation::ObservationUnavailable(
            "no privileged helper socket is configured".to_owned(),
        );
    };
    let client = match crate::privileged_helper::PrivilegedCommandClient::new(
        socket.to_path_buf(),
        helper_timeout,
    ) {
        Ok(client) => client,
        Err(e) => return ServiceDnsObservation::ObservationUnavailable(e),
    };
    observe_service_dns_postures_with(
        || {
            let output = client.run_capture(
                crate::privileged_helper::PrivilegedCommandProgram::NetworkSetup,
                &networksetup_listall_args(),
            )?;
            if !output.success() {
                return Err(format!(
                    "networksetup -listallnetworkservices failed: status={} stderr={}",
                    output.status, output.stderr
                ));
            }
            Ok(output.stdout)
        },
        |service| {
            let argv = networksetup_getdns_args(service)?;
            let output = client.run_capture(
                crate::privileged_helper::PrivilegedCommandProgram::NetworkSetup,
                &argv,
            )?;
            if !output.success() {
                return Err(format!(
                    "networksetup -getdnsservers failed: status={} stderr={}",
                    output.status, output.stderr
                ));
            }
            Ok(output.stdout)
        },
    )
}

/// The observation round-trip shape over injected enumerate/`getdns` runners
/// (pure; tests fake the helpers). Issues exactly the module's allowlisted
/// argv forms via the existing builders: one
/// `networksetup_listallnetworkservices` read, then one
/// `networksetup -getdnsservers <service>` per enumerated enabled service.
/// Any failure degrades the WHOLE observation (the guard falls back to the
/// scutil-only signal) rather than acting on a partial view.
pub fn observe_service_dns_postures_with(
    mut enumerate: impl FnMut() -> Result<String, String>,
    mut getdns: impl FnMut(&str) -> Result<String, String>,
) -> ServiceDnsObservation {
    let services = match enumerate() {
        Ok(stdout) => match parse_networksetup_service_list(&stdout) {
            Ok(services) => services,
            Err(e) => {
                return ServiceDnsObservation::ObservationUnavailable(format!(
                    "service enumeration unparsable: {e}"
                ));
            }
        },
        Err(e) => {
            return ServiceDnsObservation::ObservationUnavailable(format!(
                "service enumeration failed: {e}"
            ));
        }
    };
    let mut postures = Vec::with_capacity(services.len());
    for service in &services {
        match getdns(service) {
            Ok(stdout) => match classify_getdns_output(&stdout) {
                Ok(posture) => postures.push((service.clone(), posture)),
                Err(e) => {
                    return ServiceDnsObservation::ObservationUnavailable(format!(
                        "per-service DNS read for {service:?} unparsable: {e}"
                    ));
                }
            },
            Err(e) => {
                return ServiceDnsObservation::ObservationUnavailable(format!(
                    "per-service DNS read for {service:?} failed: {e}"
                ));
            }
        }
    }
    ServiceDnsObservation::Observed(postures)
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
        "RustyNet DNS fail-closed residue detected at startup: System Configuration DNS is still loopback but no RustyNet DNS protection is running and the backup document is missing or unreadable ({NETWORKSETUP_DNS_BACKUP_PATH}). Host DNS resolution will stay broken until the manual fix is applied:\n{per_service}\nThen restart rustynetd."
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
/// S4 widening: residue evidence is no longer the scutil primary resolver
/// alone. The guard also observes every enabled service's DNS through the
/// privileged helper (`observe_service_dns_postures`), so a crash mid-pin
/// that left a non-primary service pinned loopback is detected even when the
/// scutil primary is clean. When that observation is unavailable the guard
/// degrades rather than strands: it proceeds with the scutil-only signal and
/// emits a loud warning naming the blind spot (refusal is reserved for
/// confirmed-residue + unrecoverable; S1's runtime posture assert closes the
/// degraded window within one cadence).
///
/// `helper_socket_path` is the daemon's privileged-helper socket (when one is
/// configured); restoring and observing require it, because
/// `networksetup -setdnsservers` / `-getdnsservers` are privileged
/// operations.
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
    let observation = observe_service_dns_postures(helper_socket_path, helper_timeout);
    if let ServiceDnsObservation::ObservationUnavailable(reason) = &observation {
        log::warn!("{}", observation_unavailable_warning(reason));
    }
    let residue_evidence = residue_evidence_from_observation(sc_dns_is_loopback, &observation);
    let backup = read_networksetup_dns_backup(std::path::Path::new(NETWORKSETUP_DNS_BACKUP_PATH));
    let backup_readable = matches!(backup, Ok(Some(_)));
    match decide_startup_recovery(residue_evidence, false, backup_readable) {
        StartupRecoveryDecision::NoAction => Ok(()),
        StartupRecoveryDecision::FailLoudManualRestoreRequired => {
            // S4: name the OBSERVED loopback-pinned services (with the
            // backup's recorded entries as fallback), so the loud refusal is
            // actionable even when the backup is missing or corrupt.
            let services = fail_loud_service_list(&observation, &backup);
            if services.is_empty() {
                // Neither observation nor backup yielded a concrete name:
                // still loud, still actionable — name the fix shape and the
                // backup path.
                return Err(format!(
                    "RustyNet DNS fail-closed residue detected at startup: System Configuration DNS is loopback, no RustyNet DNS protection is running, and the backup at {NETWORKSETUP_DNS_BACKUP_PATH} is missing or unreadable. List services with `networksetup -listallnetworkservices` and restore each with:\n  sudo {NETWORKSETUP_BINARY_PATH} -setdnsservers \"<service>\" {NETWORKSETUP_EMPTY_DNS_KEYWORD}\nThen restart rustynetd."
                ));
            }
            Err(startup_recovery_manual_restore_message(&services))
        }
        StartupRecoveryDecision::RestoreFromBackup => {
            let Some(socket) = helper_socket_path else {
                return Err(format!(
                    "RustyNet DNS fail-closed residue detected at startup: System Configuration DNS is loopback and a backup exists at {NETWORKSETUP_DNS_BACKUP_PATH}, but no privileged helper socket is configured, so the automatic restore cannot run. Restore manually with `sudo {NETWORKSETUP_BINARY_PATH} -setdnsservers \"<service>\" {NETWORKSETUP_EMPTY_DNS_KEYWORD}` per service, then restart rustynetd."
                ));
            };
            let backup = match backup {
                Ok(Some(backup)) => backup,
                // Locally provable invariant (RestoreFromBackup ⇒ backup
                // readable), but fail closed anyway instead of panicking.
                _ => {
                    return Err(format!(
                        "the networksetup DNS backup at {NETWORKSETUP_DNS_BACKUP_PATH} became unreadable during startup recovery; restore manually"
                    ));
                }
            };
            let client = crate::privileged_helper::PrivilegedCommandClient::new(
                socket.to_path_buf(),
                helper_timeout,
            )?;
            for entry in &backup.services {
                let argv = startup_restore_argv_for_entry(entry)?;
                let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
                let output = client.run_capture(
                    crate::privileged_helper::PrivilegedCommandProgram::NetworkSetup,
                    &argv_refs,
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
            // S4-A2: verify the restore actually cleared residue before
            // deleting the backup. The backup only covers the services it
            // recorded; a service observed loopback-pinned but absent from
            // the backup would otherwise survive silently once the backup is
            // removed.
            let post = observe_service_dns_postures(helper_socket_path, helper_timeout);
            match &post {
                ServiceDnsObservation::Observed(_) => {
                    let survivors = surviving_loopback_services(&post);
                    if survivors.is_empty() {
                        // Residue confirmed cleared: retire the backup.
                        remove_networksetup_dns_backup(std::path::Path::new(
                            NETWORKSETUP_DNS_BACKUP_PATH,
                        ))?;
                        log::info!(
                            "rustynetd startup: restored pre-protection networksetup DNS from backup (M1 startup recovery)"
                        );
                        Ok(())
                    } else {
                        // Restore did NOT clear residue (an observed-loopback
                        // service is absent from the backup): fail loud,
                        // retain the backup, name the manual fix.
                        Err(format!(
                            "RustyNet DNS fail-closed startup recovery: the automatic backup restore completed, but these services remain loopback-pinned and are not covered by the backup at {}: {}. Backup RETAINED at {}. Restore each manually with `sudo {NETWORKSETUP_BINARY_PATH} -setdnsservers \"<service>\" {NETWORKSETUP_EMPTY_DNS_KEYWORD}`, then restart rustynetd.",
                            NETWORKSETUP_DNS_BACKUP_PATH,
                            surviving_loopback_services(&post).join(", "),
                            NETWORKSETUP_DNS_BACKUP_PATH,
                        ))
                    }
                }
                ServiceDnsObservation::ObservationUnavailable(reason) => {
                    // Degrade-not-strand: the backup restore itself
                    // succeeded, so the host is not stranded — but the
                    // post-restore verification could not run, so this is
                    // never silent. Retire the backup (it did its job for the
                    // services it covered) and name the blind spot.
                    remove_networksetup_dns_backup(std::path::Path::new(
                        NETWORKSETUP_DNS_BACKUP_PATH,
                    ))?;
                    log::warn!(
                        "RustyNet DNS fail-closed startup guard: post-restore DNS observation unavailable ({reason}); loopback residue in services absent from the backup at {NETWORKSETUP_DNS_BACKUP_PATH} may persist until the first apply. The backup restore itself completed."
                    );
                    log::info!(
                        "rustynetd startup: restored pre-protection networksetup DNS from backup (M1 startup recovery)"
                    );
                    Ok(())
                }
            }
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
    fn service_list_parser_skips_legend_wording_variants_and_disabled_entries() {
        // Field-observed macOS variants of the legend: with and without
        // "currently". Both must be recognized as structural output, never
        // as service names (an unrecognized variant previously became a
        // phantom service and failed every later `networksetup` call against
        // it with status 4). Disabled `*` entries are likewise never
        // enumerable (§5 owner decision 2).
        let short_variant = "An asterisk (*) denotes that a network service is disabled.";
        let long_variant = NETWORKSETUP_SERVICE_LIST_LEGEND;
        let output =
            format!("{short_variant}\nWi-Fi\n*Thunderbolt Bridge\n{long_variant}\nEthernet\n");
        let parsed = parse_networksetup_service_list(&output).expect("variant list must parse");
        assert_eq!(
            parsed,
            vec!["Wi-Fi".to_owned(), "Ethernet".to_owned()],
            "neither legend variant nor a disabled service may be enumerable"
        );

        // The substring predicate itself: exact consts, and a line that
        // merely CONTAINS the invariant phrase, all classify as legend.
        assert!(is_networksetup_service_list_legend(short_variant));
        assert!(is_networksetup_service_list_legend(long_variant));
        assert!(!is_networksetup_service_list_legend("Wi-Fi"));
        assert!(!is_networksetup_service_list_legend("Ethernet 2"));

        // Variant-legend-only output is still an error (no enabled services),
        // never an empty success.
        let err = parse_networksetup_service_list(short_variant)
            .expect_err("legend-only output must not parse as an empty success");
        assert!(err.contains("no enabled services"));
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

        let hostile = "{\"schema_version\": 1, \"services\": [{\"service\": \"bad\\nname\", \"servers\": null}]}";
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

    // ---- S4: startup guard sees partial per-service SC loopback residue ----

    /// A fake per-service getdns reply for a service pinned to the loopback
    /// resolvers M1 enforces.
    fn loopback_getdns_output() -> String {
        "127.0.0.1\n".to_owned()
    }

    #[test]
    fn service_observation_classifies_none_loopback_and_nonloopback() {
        assert_eq!(
            classify_getdns_output("There aren't any DNS Servers set on Wi-Fi.\n")
                .expect("none reply"),
            ServiceDnsPosture::None
        );
        assert_eq!(
            classify_getdns_output("127.0.0.1\n::1\n").expect("loopback list"),
            ServiceDnsPosture::LoopbackOnly
        );
        assert_eq!(
            classify_getdns_output("8.8.8.8\n").expect("real resolver"),
            ServiceDnsPosture::NonLoopback
        );
        // A mixed list is NOT the pure loopback pin posture.
        assert_eq!(
            classify_getdns_output("127.0.0.1\n8.8.8.8\n").expect("mixed list"),
            ServiceDnsPosture::NonLoopback
        );
        // Unparsable shapes are errors, never a classification guess.
        assert!(classify_getdns_output("").is_err());
        assert!(classify_getdns_output("some error text\n").is_err());
        assert!(classify_getdns_output("8.8.8.8\nnot-an-ip\n").is_err());
    }

    #[test]
    fn widened_decision_service_only_residue_with_readable_backup_restores() {
        // Service-only residue (scutil primary clean) + readable backup:
        // restore.
        let observation = ServiceDnsObservation::Observed(vec![
            ("Wi-Fi".to_owned(), ServiceDnsPosture::NonLoopback),
            ("Ethernet".to_owned(), ServiceDnsPosture::LoopbackOnly),
        ]);
        let residue = residue_evidence_from_observation(false, &observation);
        assert!(residue, "an observed loopback-only pin is residue evidence");
        assert_eq!(
            decide_startup_recovery(residue, false, true),
            StartupRecoveryDecision::RestoreFromBackup
        );
    }

    #[test]
    fn widened_decision_service_only_residue_without_backup_fails_loud() {
        let observation = ServiceDnsObservation::Observed(vec![(
            "Ethernet".to_owned(),
            ServiceDnsPosture::LoopbackOnly,
        )]);
        let residue = residue_evidence_from_observation(false, &observation);
        assert_eq!(
            decide_startup_recovery(residue, false, false),
            StartupRecoveryDecision::FailLoudManualRestoreRequired
        );
    }

    #[test]
    fn widened_decision_no_residue_is_no_action_regardless_of_backup() {
        // Every service observed non-loopback (or with no servers), scutil
        // clean: no residue evidence, no action — even with a backup around.
        let observation = ServiceDnsObservation::Observed(vec![
            ("Wi-Fi".to_owned(), ServiceDnsPosture::NonLoopback),
            ("Ethernet".to_owned(), ServiceDnsPosture::None),
        ]);
        assert!(!residue_evidence_from_observation(false, &observation));
        assert_eq!(
            decide_startup_recovery(false, false, true),
            StartupRecoveryDecision::NoAction
        );
        assert_eq!(
            decide_startup_recovery(false, false, false),
            StartupRecoveryDecision::NoAction
        );
        // Protection running still owns a loopback posture (unchanged rule).
        assert_eq!(
            decide_startup_recovery(true, true, true),
            StartupRecoveryDecision::NoAction
        );
    }

    #[test]
    fn partial_residue_with_clean_scutil_primary_is_detected() {
        // THE S4 REGRESSION: a crash mid-pin left a SECONDARY service pinned
        // loopback while the scutil primary resolver reports a real
        // resolver. The pre-fix guard derived residue solely from scutil and
        // took NoAction (silent strand); the widened guard must restore from
        // the surviving backup instead.
        let observation = ServiceDnsObservation::Observed(vec![
            ("Wi-Fi".to_owned(), ServiceDnsPosture::NonLoopback),
            ("Ethernet".to_owned(), ServiceDnsPosture::LoopbackOnly),
        ]);
        let residue = residue_evidence_from_observation(false, &observation);
        assert_eq!(
            decide_startup_recovery(residue, false, true),
            StartupRecoveryDecision::RestoreFromBackup,
            "a loopback-pinned secondary service with a clean scutil primary is partial residue and must be restored, not ignored"
        );
        // Same scenario with scutil reporting nothing at all (the None means
        // "no scutil evidence", pre-fix treated as false).
        assert_eq!(
            decide_startup_recovery(
                residue_evidence_from_observation(false, &observation),
                false,
                true
            ),
            StartupRecoveryDecision::RestoreFromBackup
        );
    }

    #[test]
    fn fail_loud_message_names_observed_services() {
        // Residue evidence with no readable backup: the refusal must name the
        // observed loopback-pinned services, not merely a backup-shape hint.
        let observation = ServiceDnsObservation::Observed(vec![
            ("Wi-Fi".to_owned(), ServiceDnsPosture::NonLoopback),
            ("Ethernet".to_owned(), ServiceDnsPosture::LoopbackOnly),
            (
                "Thunderbolt Bridge".to_owned(),
                ServiceDnsPosture::LoopbackOnly,
            ),
        ]);
        let no_backup: Result<Option<NetworksetupDnsBackup>, String> = Ok(None);
        let services = fail_loud_service_list(&observation, &no_backup);
        assert_eq!(
            services,
            vec!["Ethernet".to_owned(), "Thunderbolt Bridge".to_owned()]
        );
        let message = startup_recovery_manual_restore_message(&services);
        assert!(message.contains("-setdnsservers \"Ethernet\" Empty"));
        assert!(message.contains("-setdnsservers \"Thunderbolt Bridge\" Empty"));

        // Corrupt backup still yields the observed list (observation wins).
        let corrupt: Result<Option<NetworksetupDnsBackup>, String> =
            Err("backup parse failed".to_owned());
        assert_eq!(
            fail_loud_service_list(&observation, &corrupt),
            vec!["Ethernet".to_owned(), "Thunderbolt Bridge".to_owned()]
        );

        // Backup entries are the fallback when observation cannot name any
        // loopback service (e.g. scutil-only residue), deduplicated in order.
        let scutil_only = ServiceDnsObservation::Observed(vec![(
            "Wi-Fi".to_owned(),
            ServiceDnsPosture::NonLoopback,
        )]);
        let backup = build_networksetup_dns_backup(vec![
            NetworksetupDnsBackupEntry {
                service: "Wi-Fi".to_owned(),
                servers: Some(vec!["8.8.8.8".to_owned()]),
            },
            NetworksetupDnsBackupEntry {
                service: "Ethernet".to_owned(),
                servers: None,
            },
        ])
        .expect("valid backup");
        let services = fail_loud_service_list(&scutil_only, &Ok(Some(backup)));
        assert_eq!(services, vec!["Wi-Fi".to_owned(), "Ethernet".to_owned()]);

        // Neither source yields a name: the caller falls back to the
        // backup-shape hint message (still loud, still actionable).
        let unavailable = ServiceDnsObservation::ObservationUnavailable("helper down".to_owned());
        let empty: Result<Option<NetworksetupDnsBackup>, String> = Ok(None);
        assert!(fail_loud_service_list(&unavailable, &empty).is_empty());
    }

    #[test]
    fn observation_unavailable_degrades_without_stranding() {
        // Helper unobservable + clean scutil: degrade to the scutil-only
        // signal — NO residue evidence, so the guard must NOT refuse startup.
        let unavailable = ServiceDnsObservation::ObservationUnavailable(
            "helper socket connect failed".to_owned(),
        );
        assert!(!residue_evidence_from_observation(false, &unavailable));
        assert_eq!(
            decide_startup_recovery(false, false, false),
            StartupRecoveryDecision::NoAction
        );
        // Degradation must not suppress the scutil half either.
        assert!(residue_evidence_from_observation(true, &unavailable));
        assert_eq!(
            decide_startup_recovery(true, false, true),
            StartupRecoveryDecision::RestoreFromBackup
        );
        // The degrade path is LOUD: the warning names the blind spot.
        let warning = observation_unavailable_warning("helper socket connect failed");
        assert!(warning.contains("per-service DNS observation unavailable"));
        assert!(warning.contains("partial SC loopback residue may be missed"));
        // The observation shape itself degrades on any round-trip failure.
        let degraded = observe_service_dns_postures_with(
            || Err("privileged helper connect failed: no socket".to_owned()),
            |_| Ok(loopback_getdns_output()),
        );
        assert_eq!(
            degraded,
            ServiceDnsObservation::ObservationUnavailable(
                "service enumeration failed: privileged helper connect failed: no socket"
                    .to_owned()
            )
        );
        // And a per-service round-trip failure degrades the whole
        // observation (never a partial view).
        let degraded_mid = observe_service_dns_postures_with(
            || {
                Ok(format!(
                    "{NETWORKSETUP_SERVICE_LIST_LEGEND}\nWi-Fi\nEthernet\n"
                ))
            },
            |service| {
                if service == "Ethernet" {
                    Err("networksetup -getdnsservers failed: status=1".to_owned())
                } else {
                    Ok(loopback_getdns_output())
                }
            },
        );
        assert!(matches!(
            degraded_mid,
            ServiceDnsObservation::ObservationUnavailable(_)
        ));
    }

    #[test]
    fn restore_heals_exactly_backup_entries() {
        // Pin the restore loop's per-entry behavior: every recorded backup
        // entry maps to exactly one allowlisted restore argv (exact list or
        // Empty), in document order — the widened guard must not be able to
        // regress what the restore heals.
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
        let restored: Vec<Vec<String>> = backup
            .services
            .iter()
            .map(startup_restore_argv_for_entry)
            .collect::<Result<Vec<_>, _>>()
            .expect("every backup entry must yield a valid restore argv");
        assert_eq!(
            restored,
            vec![
                vec![
                    "-setdnsservers".to_owned(),
                    "Wi-Fi".to_owned(),
                    "8.8.8.8".to_owned(),
                    "1.1.1.1".to_owned(),
                ],
                vec![
                    "-setdnsservers".to_owned(),
                    "Ethernet".to_owned(),
                    NETWORKSETUP_EMPTY_DNS_KEYWORD.to_owned(),
                ],
            ]
        );
        // A recorded server list that fails argv validation can never cross
        // the helper boundary — the loop errors instead of guessing.
        let hostile = NetworksetupDnsBackupEntry {
            service: "Wi-Fi".to_owned(),
            servers: Some(vec!["not-an-ip".to_owned()]),
        };
        assert!(startup_restore_argv_for_entry(&hostile).is_err());
    }

    #[test]
    fn observation_through_helper_uses_allowlisted_argv_only() {
        // The S4 observation must issue EXACTLY the allowlisted argv forms —
        // one `-listallnetworkservices` read, then one `-getdnsservers
        // <service>` per enumerated enabled service — and nothing else (no
        // argv side door).
        // `issued` is shared between two FnMut closures, so it needs interior
        // mutability (two simultaneous `&mut` captures are E0499). RefCell is
        // the right tool in a single-threaded test; borrows are released at the
        // end of each `push` expression, well before the other closure runs.
        let issued: std::cell::RefCell<Vec<Vec<String>>> = std::cell::RefCell::new(Vec::new());
        let observation = observe_service_dns_postures_with(
            || {
                issued.borrow_mut().push(
                    networksetup_listall_args()
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                );
                Ok(format!(
                    "{NETWORKSETUP_SERVICE_LIST_LEGEND}\nWi-Fi\n*Bluetooth PAN\nEthernet\n"
                ))
            },
            |service| {
                issued.borrow_mut().push(
                    networksetup_getdns_args(service)
                        .expect("test service names are valid")
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                );
                if service == "Ethernet" {
                    Ok("8.8.8.8\n".to_owned())
                } else {
                    Ok(loopback_getdns_output())
                }
            },
        );
        // Both closures have returned; reclaim the plain Vec for assertions.
        let issued = issued.into_inner();
        assert_eq!(
            observation,
            ServiceDnsObservation::Observed(vec![
                ("Wi-Fi".to_owned(), ServiceDnsPosture::LoopbackOnly),
                ("Ethernet".to_owned(), ServiceDnsPosture::NonLoopback),
            ])
        );
        assert_eq!(
            issued,
            vec![
                vec!["-listallnetworkservices".to_owned()],
                vec!["-getdnsservers".to_owned(), "Wi-Fi".to_owned()],
                vec!["-getdnsservers".to_owned(), "Ethernet".to_owned()],
            ]
        );
        // Disabled services are never observed (out of M1 scope, §5.2).
        assert!(
            !issued
                .iter()
                .any(|argv| argv.contains(&"Bluetooth PAN".to_owned()))
        );
    }

    // ---- S4-A1/S4-A2: adversarial hardening of the startup-guard seam ----

    #[test]
    fn observation_unavailable_on_any_per_service_error() {
        // S4-A1 pin: one failing per-service read degrades the WHOLE
        // observation — never a partial Observed view.
        let observation = observe_service_dns_postures_with(
            || Ok(SAMPLE_SERVICE_LIST.to_owned()),
            |service| {
                if service == "Wi-Fi" {
                    Ok(loopback_getdns_output())
                } else {
                    Err("getdns probe failed".to_owned())
                }
            },
        );
        assert!(matches!(
            observation,
            ServiceDnsObservation::ObservationUnavailable(_)
        ));
        // The enumerate step errors the same way: whole observation degrades.
        let observation = observe_service_dns_postures_with(
            || Err("listallnetworkservices failed".to_owned()),
            |_| Ok(loopback_getdns_output()),
        );
        assert!(matches!(
            observation,
            ServiceDnsObservation::ObservationUnavailable(_)
        ));
    }

    #[test]
    fn observed_loopback_service_missing_from_backup_fails_loud_not_silent_restore() {
        // S4-A2 pin: the pure survivor list the restore arm must tri-state on.
        // One loopback-pinned survivor among an observed set.
        let observation = ServiceDnsObservation::Observed(vec![
            ("Wi-Fi".to_owned(), ServiceDnsPosture::LoopbackOnly),
            ("Ethernet".to_owned(), ServiceDnsPosture::NonLoopback),
        ]);
        assert_eq!(
            surviving_loopback_services(&observation),
            vec!["Wi-Fi".to_owned()]
        );
        // All clean: no survivors, the restore may retire the backup.
        let observation = ServiceDnsObservation::Observed(vec![
            ("Wi-Fi".to_owned(), ServiceDnsPosture::NonLoopback),
            ("Ethernet".to_owned(), ServiceDnsPosture::None),
        ]);
        assert!(surviving_loopback_services(&observation).is_empty());
        // An unavailable observation never manufactures a survivor list.
        let observation = ServiceDnsObservation::ObservationUnavailable(
            "helper socket connect failed".to_owned(),
        );
        assert!(surviving_loopback_services(&observation).is_empty());
    }
}
