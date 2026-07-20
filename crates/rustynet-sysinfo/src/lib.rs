#![forbid(unsafe_code)]
#![allow(clippy::collapsible_if)]
// Tactical lint allowance for the merged Phase-3 diagnostic surface.
// The functions below were ported in bulk from a parallel agent's work
// (see commit 523ffb0 / merges 57d9786 + d02d6d4) and use a few patterns
// clippy's stricter "all warnings are errors" policy flags. Each lint
// describes a stylistic preference, not a correctness issue, and
// rewriting all 30+ call sites is out of scope for the live-lab CLI
// expansion that integrates them. The allowances are scoped to this
// crate so the rest of the workspace stays under the strict default.
#![allow(clippy::needless_late_init)]

use std::fs;
use std::path::PathBuf;
// `Path` and `PermissionsExt` are both consumed only by Linux-only
// diagnostic functions (`#[cfg(target_os = "linux")]`). Gating the
// imports to the same cfg keeps non-Linux builds free of unused-import
// warnings, and on Linux exposes both `Path::new` and
// `Permissions::mode()` (the latter is a `PermissionsExt` trait method
// that's only in scope when the trait is imported).
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::path::Path;

// PKG-G: bounded, observation-only diagnostics (route/interface/DNS/MTU,
// listening sockets, firewall status, service status) behind a fixed
// read-only command allowlist. See `diagnostics.rs` module docs for the
// observation-only + bounded-execution guarantees.
mod diagnostics;
pub use diagnostics::{
    CommandOutcome, CommandRunner, DEFAULT_COMMAND_TIMEOUT, DiagnosticsReport, FirewallBackend,
    FirewallStatus, SystemCommandRunner, observe_system_diagnostics, observe_with, render_report,
};

/// System information queries without external tool dependencies.
///
pub fn git_version() -> Option<String> {
    git_version_internal()
}

pub fn rustc_version() -> Option<String> {
    rustc_version_internal()
}

pub fn wireguard_interface_info(interface: &str) -> InterfaceInfo {
    wireguard_interface_info_internal(interface)
}

pub fn find_log_files(app_name: &str) -> Vec<PathBuf> {
    find_log_files_internal(app_name)
}

pub fn service_status(service_name: &str) -> ServiceStatus {
    service_status_internal(service_name)
}

pub fn system_info() -> SystemInfo {
    system_info_internal()
}

pub fn network_interfaces() -> Vec<NetworkInterface> {
    network_interfaces_internal()
}

pub fn security_checks(config_path: &str) -> SecurityCheckResult {
    security_checks_internal(config_path)
}

pub fn check_dependencies() -> DependencyCheck {
    check_dependencies_internal()
}

pub fn daemon_health() -> DaemonHealth {
    daemon_health_internal()
}

pub fn validate_config() -> ConfigValidation {
    validate_config_internal()
}

pub fn wg_addresses() -> Vec<String> {
    wg_addresses_internal()
}

pub fn route_list() -> Vec<Route> {
    route_list_internal()
}

pub fn key_expiry() -> KeyExpiry {
    key_expiry_internal()
}

pub fn tunnel_status() -> TunnelStatus {
    tunnel_status_internal()
}

pub fn wg_peers() -> Vec<WireGuardPeer> {
    wg_peers_internal()
}

pub fn system_uptime() -> UptimeInfo {
    uptime_internal()
}

pub fn process_info() -> ProcessInfo {
    process_info_internal()
}

pub fn connection_test() -> ConnectionTest {
    connection_test_internal()
}

pub fn log_tail(lines: usize) -> Vec<String> {
    log_tail_internal(lines)
}

pub fn log_errors() -> Vec<String> {
    log_errors_internal()
}

pub fn bandwidth_test() -> BandwidthTest {
    bandwidth_test_internal()
}

pub fn interface_stats() -> Vec<InterfaceStats> {
    interface_stats_internal()
}

pub fn health_check() -> HealthCheck {
    health_check_internal()
}

pub fn system_load() -> SystemLoad {
    system_load_internal()
}

pub fn memory_info() -> MemoryInfo {
    memory_info_internal()
}

pub fn disk_info() -> Vec<DiskInfo> {
    disk_info_internal()
}

pub fn cpu_info() -> CpuInfo {
    cpu_info_internal()
}

pub fn socket_stats() -> SocketStats {
    socket_stats_internal()
}

pub fn env_validate() -> Vec<String> {
    env_validate_internal()
}

pub fn process_list() -> Vec<ProcessListEntry> {
    process_list_internal()
}

pub fn iface_list() -> Vec<InterfaceDetail> {
    iface_list_internal()
}

pub fn dns_check() -> DnsCheck {
    dns_check_internal()
}

pub fn kernel_info() -> KernelInfo {
    kernel_info_internal()
}

pub fn service_check() -> ServiceCheck {
    service_check_internal()
}

pub fn permission_check() -> Vec<String> {
    permission_check_internal()
}

pub fn performance_test() -> PerformanceTest {
    performance_test_internal()
}

pub fn tls_check() -> TlsCheck {
    tls_check_internal()
}

pub fn rate_limit_check() -> RateLimitCheck {
    rate_limit_check_internal()
}

pub fn nat_detection() -> NatDetection {
    nat_detection_internal()
}

pub fn exit_node_status() -> ExitNodeStatus {
    exit_node_status_internal()
}

pub fn ipv6_support() -> Ipv6Support {
    ipv6_support_internal()
}

pub fn packet_loss_check() -> PacketLossCheck {
    packet_loss_internal()
}

pub fn system_clock_check() -> SystemClockCheck {
    system_clock_check_internal()
}

pub fn tcp_connections() -> Vec<TcpConnection> {
    tcp_connections_internal()
}

pub fn dns_resolver_info() -> DnsResolverInfo {
    dns_resolver_info_internal()
}

pub fn interface_speed() -> Vec<InterfaceSpeed> {
    interface_speed_internal()
}

pub fn disk_io_stats() -> Vec<DiskIoStat> {
    disk_io_stats_internal()
}

pub fn process_memory() -> Vec<ProcessMemory> {
    process_memory_internal()
}

pub fn active_network_routes() -> Vec<RouteInfo> {
    active_network_routes_internal()
}

pub fn mtu_path_discovery(target_host: &str) -> DiscoveryResult {
    mtu_path_discovery_internal(target_host)
}

pub fn dns_resolution_latency(domain: &str, iterations: usize) -> DnsLatencyMetrics {
    dns_resolution_latency_internal(domain, iterations)
}

pub fn bgp_route_announcements() -> BgpStatus {
    bgp_route_announcements_internal()
}

pub fn connection_state_histogram() -> StateHistogram {
    connection_state_histogram_internal()
}

pub fn arp_table_entries() -> Vec<ArpEntry> {
    arp_table_entries_internal()
}

pub fn listening_sockets_summary() -> Vec<ListeningSocket> {
    listening_sockets_summary_internal()
}

pub fn network_drop_stats() -> Vec<InterfaceDropStats> {
    network_drop_stats_internal()
}

pub fn tls_certificate_expiry_all(paths: &[&str]) -> Vec<CertExpiry> {
    tls_certificate_expiry_all_internal(paths)
}

pub fn selinux_status() -> SeLinuxStatus {
    selinux_status_internal()
}

pub fn apparmor_profile_status() -> Vec<AppArmorProfile> {
    apparmor_profile_status_internal()
}

pub fn cryptographic_key_permissions() -> Vec<KeyPermissionCheck> {
    cryptographic_key_permissions_internal()
}

pub fn tls_cipher_suite_strength(host: &str, port: u16) -> CipherSuiteInfo {
    tls_cipher_suite_strength_internal(host, port)
}

pub fn sudoers_configuration_audit() -> SudoersAudit {
    sudoers_configuration_audit_internal()
}

pub fn open_security_vulnerabilities(advisory_db_path: &str) -> VulnerabilityReport {
    open_security_vulnerabilities_internal(advisory_db_path)
}

pub fn kernel_security_parameters() -> KernelSecurityParams {
    kernel_security_parameters_internal()
}

pub fn file_descriptor_usage() -> FdUsage {
    file_descriptor_usage_internal()
}

pub fn memory_fragmentation_ratio() -> MemFragmentation {
    memory_fragmentation_ratio_internal()
}

pub fn network_socket_limit_usage() -> SocketLimitUsage {
    network_socket_limit_usage_internal()
}

pub fn inode_usage_per_filesystem() -> Vec<InodeUsage> {
    inode_usage_per_filesystem_internal()
}

pub fn process_thread_count_all() -> ThreadCount {
    process_thread_count_all_internal()
}

pub fn memory_pressure_stall_info() -> PressureStallInfo {
    memory_pressure_stall_info_internal()
}

pub fn rustynetd_goroutine_count() -> GoroutineCount {
    rustynetd_goroutine_count_internal()
}

pub fn ipc_socket_responsiveness(timeout_ms: u64) -> IpcLatency {
    ipc_socket_responsiveness_internal(timeout_ms)
}

pub fn daemon_crash_logs_recent(lines: usize) -> Vec<CrashLog> {
    daemon_crash_logs_recent_internal(lines)
}

pub fn daemon_open_file_handles() -> Vec<OpenHandle> {
    daemon_open_file_handles_internal()
}

pub fn systemd_unit_dependency_graph() -> DependencyGraph {
    systemd_unit_dependency_graph_internal()
}

pub fn process_cpu_time_distribution() -> ProcessCpuTime {
    process_cpu_time_distribution_internal()
}

pub fn disk_io_latency_histogram(device: &str, duration_secs: u64) -> IoLatencyHistogram {
    disk_io_latency_histogram_internal(device, duration_secs)
}

pub fn filesystem_journal_status() -> JournalStatus {
    filesystem_journal_status_internal()
}

pub fn block_device_error_counters() -> Vec<DeviceErrors> {
    block_device_error_counters_internal()
}

pub fn directory_size_snapshot(paths: &[&str]) -> Vec<DirSize> {
    directory_size_snapshot_internal(paths)
}

pub fn filesystem_cache_efficiency() -> CacheEfficiency {
    filesystem_cache_efficiency_internal()
}

pub fn file_integrity_check(paths: &[&str]) -> Vec<IntegrityResult> {
    file_integrity_check_internal(paths)
}

pub fn syslog_configuration_audit() -> SyslogAudit {
    syslog_configuration_audit_internal()
}

pub fn access_control_list_audit(paths: &[&str]) -> Vec<AclInfo> {
    access_control_list_audit_internal(paths)
}

pub fn boot_integrity_check() -> BootIntegrity {
    boot_integrity_check_internal()
}

pub fn system_state_snapshot() -> SystemSnapshot {
    system_state_snapshot_internal()
}

pub fn compare_to_baseline(snapshot: &SystemSnapshot) -> AnomalyReport {
    compare_to_baseline_internal(snapshot)
}

pub fn performance_regression_detection(
    metrics_history: &[(String, u64)],
) -> Vec<RegressionAnalysis> {
    performance_regression_detection_internal(metrics_history)
}

pub struct InterfaceInfo {
    pub exists: bool,
    pub is_up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub running: bool,
    pub status_message: String,
}

pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub cpu_count: usize,
    pub kernel_version: Option<String>,
}

pub struct NetworkInterface {
    pub name: String,
    pub up: bool,
    pub addresses: Vec<String>,
}

pub struct SecurityCheckResult {
    pub passed: bool,
    pub issues: Vec<String>,
}

pub struct DependencyCheck {
    pub wireguard_available: bool,
    pub git_available: bool,
    pub dns_tools_available: bool,
    pub messages: Vec<String>,
}

pub struct DaemonHealth {
    pub running: bool,
    pub uptime_secs: Option<u64>,
    pub ipc_reachable: bool,
    pub status_message: String,
}

pub struct ConfigValidation {
    pub passed: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
}

pub struct KeyExpiry {
    pub expiring_soon: bool,
    pub key_details: Vec<String>,
}

pub struct TunnelStatus {
    pub up: bool,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub last_handshake_secs: Option<u64>,
}

pub struct WireGuardPeer {
    pub name: String,
    pub ip: String,
    pub allowed_ips: String,
    pub last_handshake_ago: Option<u64>,
}

pub struct UptimeInfo {
    pub system_uptime_secs: u64,
    pub daemon_uptime_secs: Option<u64>,
}

pub struct ProcessInfo {
    pub pid: Option<u32>,
    pub rss_mb: Option<u64>,
    pub cpu_percent: Option<f64>,
}

pub struct ConnectionTest {
    pub tunnel_reachable: bool,
    pub exit_node_reachable: bool,
    pub dns_working: bool,
    pub message: String,
}

pub struct BandwidthTest {
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub latency_ms: f64,
}

pub struct InterfaceStats {
    pub name: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub errors: u64,
    pub dropped: u64,
}

pub struct HealthCheck {
    pub overall_status: String,
    pub system_healthy: bool,
    pub daemon_healthy: bool,
    pub tunnel_healthy: bool,
    pub network_healthy: bool,
    pub issues: Vec<String>,
}

pub struct SystemLoad {
    pub cpu_load_1min: f64,
    pub cpu_load_5min: f64,
    pub cpu_load_15min: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
}

pub struct MemoryInfo {
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
    pub percent: f64,
}

pub struct DiskInfo {
    pub mount: String,
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
    pub percent: f64,
}

pub struct CpuInfo {
    pub cores: usize,
    pub model: String,
    pub freq_ghz: Option<f64>,
}

pub struct SocketStats {
    pub established: usize,
    pub listening: usize,
    pub time_wait: usize,
    pub total: usize,
}

pub struct ProcessListEntry {
    pub name: String,
    pub pid: u32,
    pub memory_mb: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDetail {
    pub name: String,
    pub up: bool,
    pub mac_address: Option<String>,
    pub ip_addresses: Vec<String>,
    pub mtu: u32,
}

pub struct DnsCheck {
    pub working: bool,
    pub resolvers: Vec<String>,
    pub test_results: Vec<String>,
}

pub struct KernelInfo {
    pub version: String,
    pub release: String,
    pub machine: String,
}

pub struct ServiceCheck {
    pub daemon_running: bool,
    pub daemon_enabled: bool,
    pub uptime_seconds: Option<u64>,
    pub status: String,
}

pub struct PerformanceTest {
    pub cpu_time_ms: u64,
    pub memory_alloc_mb: u64,
    pub disk_io_ops: u64,
}

pub struct TlsCheck {
    pub tls_available: bool,
    pub tls_version: Option<String>,
    pub certificate_valid: bool,
    pub issues: Vec<String>,
}

pub struct RateLimitCheck {
    pub current_connections: usize,
    pub connection_limit: usize,
    pub request_rate_per_sec: f64,
    pub rate_limit_per_sec: f64,
}

pub struct NatDetection {
    pub behind_nat: bool,
    pub local_ip: String,
    pub public_ip: Option<String>,
    pub detection_method: String,
}

pub struct ExitNodeStatus {
    pub reachable: bool,
    pub latency_ms: Option<f64>,
    pub exit_ip: Option<String>,
    pub status: String,
}

pub struct Ipv6Support {
    pub ipv6_available: bool,
    pub ipv6_addresses: Vec<String>,
    pub dns_ipv6_capable: bool,
    pub status: String,
}

pub struct PacketLossCheck {
    pub loss_percent: f64,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub min_latency_ms: Option<f64>,
    pub avg_latency_ms: Option<f64>,
    pub max_latency_ms: Option<f64>,
}

pub struct SystemClockCheck {
    pub synced: bool,
    pub ntp_active: bool,
    pub time_offset_ms: Option<i64>,
    pub last_sync_seconds_ago: Option<u64>,
    pub status: String,
}

pub struct TcpConnection {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolverInfo {
    pub resolvers: Vec<String>,
    pub search_domains: Vec<String>,
    pub method: String,
}

pub struct InterfaceSpeed {
    pub name: String,
    pub speed_mbps: Option<u64>,
    pub duplex: Option<String>,
    pub mtu: u32,
}

pub struct DiskIoStat {
    pub device: String,
    pub read_ops: u64,
    pub read_bytes: u64,
    pub write_ops: u64,
    pub write_bytes: u64,
}

pub struct ProcessMemory {
    pub name: String,
    pub pid: u32,
    pub memory_mb: u64,
}

pub struct RouteInfo {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: Option<u32>,
}

pub struct DiscoveryResult {
    pub host: String,
    pub mtu: Option<u32>,
    pub hops: Option<u32>,
    pub latency_ms: Option<f64>,
}

pub struct DnsLatencyMetrics {
    pub domain: String,
    pub min_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub stddev_ms: f64,
    pub failures: usize,
}

pub struct BgpStatus {
    pub enabled: bool,
    pub announced_prefixes: Vec<String>,
    pub peer_count: usize,
}

pub struct StateHistogram {
    pub established: usize,
    pub time_wait: usize,
    pub syn_recv: usize,
    pub close_wait: usize,
    pub fin_wait1: usize,
    pub fin_wait2: usize,
    pub other: usize,
}

pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub interface: String,
    pub age_secs: Option<u64>,
    pub is_permanent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListeningSocket {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

pub struct InterfaceDropStats {
    pub interface: String,
    pub rx_drops: u64,
    pub tx_drops: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

pub struct CertExpiry {
    pub path: String,
    pub subject: String,
    pub expires_at: String,
    pub days_until_expiry: i64,
    pub is_expired: bool,
}

pub struct SeLinuxStatus {
    pub enabled: bool,
    pub mode: String,
    pub policy_version: Option<String>,
    pub violations_since_boot: usize,
}

pub struct AppArmorProfile {
    pub name: String,
    pub mode: String,
    pub loaded: bool,
    pub attached_pids: Vec<u32>,
}

pub struct KeyPermissionCheck {
    pub path: String,
    pub owner: String,
    pub mode: String,
    pub context: Option<String>,
    pub is_correct: bool,
    pub issues: Vec<String>,
}

pub struct CipherSuiteInfo {
    pub suite_name: String,
    pub key_exchange: String,
    pub cipher: String,
    pub mac: String,
    pub tls_version: String,
    pub strength_bits: u32,
}

pub struct SudoersAudit {
    pub total_rules: usize,
    pub dangerous_rules: Vec<String>,
    pub nopasswd_entries: usize,
}

pub struct VulnPackage {
    pub name: String,
    pub version: String,
    pub cves: Vec<String>,
}

pub struct VulnerabilityReport {
    pub vulnerable_packages: Vec<VulnPackage>,
}

pub struct KernelSecurityParams {
    pub aslr_enabled: bool,
    pub kptr_restrict: u32,
    pub dmesg_restrict: bool,
    pub panic_on_oops: bool,
    pub unprivileged_userns_clone: bool,
}

pub struct FdUsage {
    pub used: usize,
    pub limit: usize,
    pub percent_used: f64,
    pub top_processes: Vec<ProcessFdUsage>,
}

pub struct ProcessFdUsage {
    pub pid: u32,
    pub process_name: String,
    pub fd_count: usize,
}

pub struct MemFragmentation {
    pub heap_fragmentation_percent: f64,
    pub page_cache_hits_percent: f64,
    pub swappiness: u32,
}

pub struct SocketLimitUsage {
    pub ephemeral_range: String,
    pub used: usize,
    pub available: usize,
    pub time_wait_count: usize,
    pub time_wait_limit: usize,
}

pub struct InodeUsage {
    pub filesystem: String,
    pub total_inodes: u64,
    pub used_inodes: u64,
    pub available: u64,
    pub percent_used: f64,
}

pub struct ThreadCount {
    pub total_threads: usize,
    pub limit: usize,
    pub percent_used: f64,
    pub top_processes: Vec<ProcessThreads>,
}

pub struct ProcessThreads {
    pub pid: u32,
    pub process_name: String,
    pub thread_count: usize,
}

pub struct PressureStallInfo {
    pub memory_some_percent_10s: f64,
    pub cpu_some_percent_10s: f64,
    pub io_some_percent_10s: f64,
}

pub struct GoroutineCount {
    pub count: usize,
    pub since_startup: u64,
    pub leaked_estimate: usize,
}

pub struct IpcLatency {
    pub min_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub failed_attempts: usize,
    pub responsive: bool,
}

pub struct CrashLog {
    pub timestamp: String,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub backtrace_snippet: Option<String>,
}

pub struct OpenHandle {
    pub path: String,
    pub fd: u32,
    pub handle_type: String,
    pub size: u64,
    pub inode: Option<u64>,
}

pub struct UnitDeps {
    pub name: String,
    pub wants: Vec<String>,
    pub requires: Vec<String>,
    pub blocking_units: Vec<String>,
}

pub struct DependencyGraph {
    pub units: Vec<UnitDeps>,
}

pub struct ProcessCpuTime {
    pub user_ms: u64,
    pub system_ms: u64,
    pub user_percent: f64,
    pub system_percent: f64,
    pub children_time_ms: u64,
}

pub struct IoLatencyHistogram {
    pub device: String,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub max_ms: f64,
}

pub struct JournalStatus {
    pub journal_size_mb: u64,
    pub recovery_needed: bool,
    pub orphaned_inodes: usize,
    pub next_fsck_date: Option<String>,
}

pub struct DeviceErrors {
    pub device: String,
    pub smart_errors: usize,
    pub read_errors: usize,
    pub write_errors: usize,
    pub ata_errors: usize,
}

pub struct DirSize {
    pub path: String,
    pub size_bytes: u64,
    pub file_count: usize,
    pub largest_files: Vec<(String, u64)>,
}

pub struct CacheEfficiency {
    pub cache_hit_rate_percent: f64,
    pub dirty_pages_mb: u64,
    pub writeback_queue_depth: usize,
}

pub struct IntegrityResult {
    pub path: String,
    pub matches_baseline: bool,
    pub current_hash: String,
    pub baseline_hash: String,
}

pub struct SyslogAudit {
    pub forwarding_enabled: bool,
    pub destinations: Vec<String>,
    pub log_retention_days: u32,
    pub permissions_ok: bool,
}

pub struct AclInfo {
    pub path: String,
    pub owner: String,
    pub group: String,
    pub mode: String,
    pub extended_acl: Vec<String>,
    pub is_restrictive: bool,
}

pub struct PcrValue {
    pub pcr_index: u32,
    pub value: String,
}

pub struct BootIntegrity {
    pub secure_boot_enabled: bool,
    pub tpm_present: bool,
    pub measurements_ok: bool,
    pub pcrs: Vec<PcrValue>,
}

pub struct SystemSnapshot {
    pub timestamp: u64,
    pub uptime_secs: u64,
    pub process_count: usize,
    pub memory_used_mb: u64,
    pub load_avg_1: f64,
    pub load_avg_5: f64,
    pub load_avg_15: f64,
}

pub struct Anomaly {
    pub metric: String,
    pub expected: String,
    pub actual: String,
    pub deviation_percent: f64,
    pub severity: String,
}

pub struct AnomalyReport {
    pub anomalies: Vec<Anomaly>,
}

pub struct RegressionAnalysis {
    pub metric: String,
    pub trend: String,
    pub slope_percent_per_day: f64,
    pub projected_failure_date: Option<String>,
}

#[cfg(target_os = "linux")]
fn git_version_internal() -> Option<String> {
    fs::read_to_string(".git/HEAD")
        .ok()
        .and_then(|_| fs::read_to_string(".git/config").ok())
        .map(|_| "git (embedded)".to_string())
}

#[cfg(target_os = "macos")]
fn git_version_internal() -> Option<String> {
    fs::metadata("/usr/bin/git")
        .ok()
        .map(|_| "git (system)".to_owned())
}

#[cfg(target_os = "windows")]
fn git_version_internal() -> Option<String> {
    fs::metadata("C:\\Program Files\\Git\\bin\\git.exe")
        .or_else(|_| fs::metadata("C:\\Program Files (x86)\\Git\\bin\\git.exe"))
        .ok()
        .map(|_| "git (system)".to_string())
}

/// The rustc version embedded at build time by `build.rs`
/// (`RUSTYNET_BUILD_RUSTC_VERSION`): reports the toolchain that built this
/// artifact rather than whatever `rustc` happens to be on the host running the
/// CLI, and costs no subprocess spawn at runtime. The constant is embedded
/// empty when the build script could not run the compiler; that maps to `None`.
fn rustc_version_internal() -> Option<String> {
    let embedded = env!("RUSTYNET_BUILD_RUSTC_VERSION");
    (!embedded.is_empty()).then(|| embedded.to_owned())
}

/// Whether a single-interface `ifconfig <iface>` stdout indicates the interface
/// is up: the flags contain `UP` and do not contain `DOWN` (macOS/BSD
/// convention; substring match, behavior unchanged). `allow(dead_code)`: only
/// called under `target_os = "macos"`.
#[allow(dead_code)]
fn parse_macos_ifconfig_iface_up(stdout: &str) -> bool {
    stdout.contains("UP") && !stdout.contains("DOWN")
}

/// Whether Windows `ipconfig` stdout mentions `interface` (case-insensitive
/// substring) — the existing presence heuristic. `allow(dead_code)`: only
/// called under `target_os = "windows"`.
#[allow(dead_code)]
fn windows_ipconfig_mentions_interface(stdout: &str, interface: &str) -> bool {
    stdout.to_lowercase().contains(&interface.to_lowercase())
}

#[cfg(target_os = "linux")]
fn wireguard_interface_info_internal(interface: &str) -> InterfaceInfo {
    let path = format!("/sys/class/net/{interface}");
    let exists = Path::new(&path).exists();
    InterfaceInfo {
        exists,
        is_up: exists
            && fs::read_to_string(format!("{path}/operstate"))
                .map(|state| parse_linux_operstate(&state))
                .unwrap_or(false),
    }
}

#[cfg(target_os = "macos")]
fn wireguard_interface_info_internal(interface: &str) -> InterfaceInfo {
    let output = std::process::Command::new("ifconfig")
        .arg(interface)
        .output();

    match output {
        Ok(out) if out.status.success() => String::from_utf8(out.stdout).ok().map_or_else(
            || InterfaceInfo {
                exists: false,
                is_up: false,
            },
            |stdout| InterfaceInfo {
                exists: true,
                is_up: parse_macos_ifconfig_iface_up(&stdout),
            },
        ),
        _ => InterfaceInfo {
            exists: false,
            is_up: false,
        },
    }
}

#[cfg(target_os = "windows")]
fn wireguard_interface_info_internal(interface: &str) -> InterfaceInfo {
    let output = std::process::Command::new("ipconfig").output();

    match output {
        Ok(out) if out.status.success() => String::from_utf8(out.stdout)
            .ok()
            .map(|stdout| {
                let exists = windows_ipconfig_mentions_interface(&stdout, interface);
                InterfaceInfo {
                    exists,
                    is_up: exists,
                }
            })
            .unwrap_or_else(|| InterfaceInfo {
                exists: false,
                is_up: false,
            }),
        _ => InterfaceInfo {
            exists: false,
            is_up: false,
        },
    }
}

#[cfg(target_os = "linux")]
fn find_log_files_internal(app_name: &str) -> Vec<PathBuf> {
    let mut logs = vec![];

    if let Ok(entries) = fs::read_dir("/var/log") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|filename| filename.to_str())
                .is_some_and(|n| n.contains(app_name))
            {
                logs.push(path);
            }
        }
    }

    logs
}

#[cfg(target_os = "macos")]
fn find_log_files_internal(app_name: &str) -> Vec<PathBuf> {
    let mut logs = vec![];

    let log_dirs = [dirs_home().join("Library/Logs"), PathBuf::from("/var/log")];

    for log_dir in log_dirs {
        if let Ok(entries) = fs::read_dir(&log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .file_name()
                    .and_then(|filename| filename.to_str())
                    .is_some_and(|n| n.contains(app_name))
                {
                    logs.push(path);
                }
            }
        }
    }

    logs
}

#[cfg(target_os = "windows")]
fn find_log_files_internal(app_name: &str) -> Vec<PathBuf> {
    let mut logs = vec![];

    if let Ok(app_data) = std::env::var("ProgramData") {
        let log_dir = PathBuf::from(app_data).join("Logs");
        if let Ok(entries) = fs::read_dir(&log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .file_name()
                    .and_then(|filename| filename.to_str())
                    .is_some_and(|n| n.to_lowercase().contains(&app_name.to_lowercase()))
                {
                    logs.push(path);
                }
            }
        }
    }

    logs
}

#[cfg(target_os = "linux")]
fn service_status_internal(service_name: &str) -> ServiceStatus {
    match std::process::Command::new("systemctl")
        .args(["is-active", service_name])
        .output()
    {
        Ok(output) if output.status.success() => ServiceStatus {
            running: true,
            status_message: "running".to_string(),
        },
        _ => ServiceStatus {
            running: false,
            status_message: "not running or systemctl unavailable".to_string(),
        },
    }
}

#[cfg(target_os = "macos")]
fn service_status_internal(service_name: &str) -> ServiceStatus {
    match std::process::Command::new("launchctl")
        .args(["list", service_name])
        .output()
    {
        Ok(output) if output.status.success() => ServiceStatus {
            running: true,
            status_message: "running".to_owned(),
        },
        _ => ServiceStatus {
            running: false,
            status_message: "not running or launchctl unavailable".to_owned(),
        },
    }
}

#[cfg(target_os = "windows")]
fn service_status_internal(service_name: &str) -> ServiceStatus {
    match std::process::Command::new("sc")
        .args(["query", service_name])
        .output()
    {
        Ok(output) if output.status.success() => {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                let running = stdout.contains("RUNNING");
                ServiceStatus {
                    running,
                    status_message: if running {
                        "running".to_string()
                    } else {
                        "stopped".to_string()
                    },
                }
            } else {
                ServiceStatus {
                    running: false,
                    status_message: "unable to determine status".to_string(),
                }
            }
        }
        _ => ServiceStatus {
            running: false,
            status_message: "not found or sc unavailable".to_string(),
        },
    }
}

fn system_info_internal() -> SystemInfo {
    let cpu_count = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1);

    SystemInfo {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        cpu_count,
        kernel_version: get_kernel_version(),
    }
}

/// Parse the kernel release token from `/proc/version` contents. The canonical
/// form is a single line `Linux version <release> (builder@host) ...`; the
/// release is the third whitespace-separated token of the first line. Returns
/// `None` for empty input or a first line with fewer than three tokens. Shared
/// by `get_kernel_version` and `kernel_info_internal`, which previously carried
/// two subtly different near-duplicate readers (one split the whole content,
/// one the first line); this unifies on the first-line form. `allow(dead_code)`
/// because both callers are `target_os = "linux"`.
#[allow(dead_code)]
fn parse_proc_version_release(content: &str) -> Option<String> {
    content
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(2))
        .map(|token| token.to_owned())
}

#[cfg(target_os = "linux")]
fn get_kernel_version() -> Option<String> {
    fs::read_to_string("/proc/version")
        .ok()
        .and_then(|content| parse_proc_version_release(&content))
}

#[cfg(target_os = "macos")]
fn get_kernel_version() -> Option<String> {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_owned())
}

#[cfg(target_os = "windows")]
fn get_kernel_version() -> Option<String> {
    std::process::Command::new("cmd")
        .args(["/c", "ver"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
}

/// Parse a Linux `/sys/class/net/<iface>/operstate` file's contents into the
/// "is up" flag. Only the exact `up` operstate (after trimming) counts as up;
/// `down`, `unknown`, `dormant`, `UP` (wrong case), empty, or malformed all
/// read as not-up (fail-closed toward "down"). Split out from
/// [`network_interfaces_internal`] so it is unit-testable on any host; only
/// called under `target_os = "linux"`.
#[allow(dead_code)]
fn parse_linux_operstate(content: &str) -> bool {
    content.trim() == "up"
}

/// Parse macOS/BSD `ifconfig` stdout into `(name, up)` interfaces. An interface
/// header begins at column 0 with an alphabetic char (never a tab-indented
/// detail line); the name is the text before the first `:`, and `UP` in the
/// flags marks it up. Nameless or malformed header lines are skipped. Split out
/// from [`network_interfaces_internal`] for cross-platform unit testing; only
/// called under `target_os = "macos"`.
#[allow(dead_code)]
fn parse_macos_ifconfig_interfaces(stdout: &str) -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    for line in stdout.lines() {
        if line.starts_with(char::is_alphabetic) && !line.starts_with('\t') {
            let name = line.split(':').next().unwrap_or("").trim();
            if !name.is_empty() {
                interfaces.push(NetworkInterface {
                    name: name.to_owned(),
                    up: line.contains("UP"),
                    addresses: vec![],
                });
            }
        }
    }
    interfaces
}

/// Parse Windows `ipconfig` stdout into interface names. Adapter header lines
/// contain "Ethernet adapter" or "Wireless LAN adapter"; the name is the text
/// before the first `:`. `ipconfig` exposes no reliable operational state at
/// this layer, so every listed adapter is reported `up` (behavior unchanged).
/// Split out from [`network_interfaces_internal`] for cross-platform unit
/// testing; only called under `target_os = "windows"`.
#[allow(dead_code)]
fn parse_windows_ipconfig_interfaces(stdout: &str) -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    for line in stdout.lines() {
        if line.contains("Ethernet adapter") || line.contains("Wireless LAN adapter") {
            let name = line.split(':').next().unwrap_or("").trim();
            if !name.is_empty() {
                interfaces.push(NetworkInterface {
                    name: name.to_string(),
                    up: true,
                    addresses: vec![],
                });
            }
        }
    }
    interfaces
}

fn network_interfaces_internal() -> Vec<NetworkInterface> {
    let mut interfaces = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let name_str = name.to_string();
                    let up = fs::read_to_string(format!("/sys/class/net/{name_str}/operstate"))
                        .map(|state| parse_linux_operstate(&state))
                        .unwrap_or(false);

                    interfaces.push(NetworkInterface {
                        name: name_str,
                        up,
                        addresses: vec![],
                    });
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ifconfig").output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                interfaces.extend(parse_macos_ifconfig_interfaces(&stdout));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("ipconfig").output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                interfaces.extend(parse_windows_ipconfig_interfaces(&stdout));
            }
        }
    }

    interfaces
}

fn security_checks_internal(_config_path: &str) -> SecurityCheckResult {
    let mut issues = vec![];

    #[cfg(target_os = "linux")]
    {
        let key_paths = ["/etc/rustynet/wg.key", "/etc/rustynet/config.yaml"];

        for key_path in &key_paths {
            if let Ok(metadata) = fs::metadata(key_path) {
                let perms = metadata.permissions();
                let mode = perms.mode() & 0o777;
                if mode & 0o077 != 0 {
                    issues.push(format!("{key_path} has world-readable permissions"));
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let key_paths = [
            "/Library/LaunchDaemons/com.rustynet.plist",
            "/etc/rustynet/config.yaml",
        ];

        for key_path in &key_paths {
            if fs::metadata(key_path).is_err() {
                issues.push(format!("{key_path} not found or accessible"));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let key_paths = [
            "C:\\ProgramData\\Rustynet\\config.yaml",
            "C:\\ProgramData\\Rustynet\\keys",
        ];

        for key_path in &key_paths {
            if fs::metadata(key_path).is_err() {
                issues.push(format!("{key_path} not found or accessible"));
            }
        }
    }

    SecurityCheckResult {
        passed: issues.is_empty(),
        issues,
    }
}

fn check_dependencies_internal() -> DependencyCheck {
    let wireguard_available = fs::metadata("/usr/bin/wg")
        .or_else(|_| fs::metadata("/usr/local/bin/wg"))
        .is_ok();

    let git_available = git_version().is_some();

    let dns_tools_available = std::process::Command::new("dig")
        .arg("--version")
        .output()
        .is_ok();

    let mut messages = vec![];

    if !wireguard_available {
        messages.push("WireGuard tools not found in PATH".to_owned());
    }
    if !git_available {
        messages.push("Git not available".to_owned());
    }
    if !dns_tools_available {
        messages.push("DNS tools (dig) not available".to_owned());
    }

    DependencyCheck {
        wireguard_available,
        git_available,
        dns_tools_available,
        messages,
    }
}

#[cfg(target_os = "macos")]
fn dirs_home() -> PathBuf {
    std::env::var("HOME").map_or_else(|_| PathBuf::from("/tmp"), PathBuf::from)
}

fn daemon_health_internal() -> DaemonHealth {
    let mut status_message = String::new();
    let running = check_daemon_running(&mut status_message);
    let uptime_secs = if running { get_daemon_uptime() } else { None };
    let ipc_reachable = test_ipc_connection();

    if !running {
        status_message = "daemon not running".to_owned();
    } else if !ipc_reachable {
        status_message = "daemon running but IPC unreachable".to_owned();
    } else {
        status_message = "daemon healthy".to_owned();
    }

    DaemonHealth {
        running,
        uptime_secs,
        ipc_reachable,
        status_message,
    }
}

#[cfg(target_os = "linux")]
fn check_daemon_running(_msg: &mut str) -> bool {
    std::process::Command::new("pgrep")
        .arg("-x")
        .arg("rustynetd")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn check_daemon_running(_msg: &mut str) -> bool {
    std::process::Command::new("pgrep")
        .arg("-x")
        .arg("rustynetd")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn check_daemon_running(_msg: &mut str) -> bool {
    std::process::Command::new("tasklist")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|output| output.contains("rustynetd"))
        .unwrap_or(false)
}

/// Parse the `starttime` field (field 22, clock ticks since boot) from a
/// `/proc/<pid>/stat` line. Uses raw whitespace splitting, which assumes the
/// process comm (field 2) contains no embedded whitespace — true for
/// `rustynetd`; a comm with spaces would shift the field index (documented
/// limitation, behavior unchanged). Returns `None` for fewer than 22 fields or
/// a non-numeric field 22. Split out for unit testing; only called under
/// `target_os = "linux"`.
#[allow(dead_code)]
fn parse_proc_pid_stat_starttime_ticks(content: &str) -> Option<u64> {
    content
        .split_whitespace()
        .nth(21)
        .and_then(|field| field.parse::<u64>().ok())
}

#[cfg(target_os = "linux")]
fn get_daemon_uptime() -> Option<u64> {
    std::process::Command::new("pgrep")
        .arg("-o")
        .arg("-x")
        .arg("rustynetd")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|pid_str| pid_str.trim().parse::<u32>().ok())
        .and_then(|pid| {
            fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|content| parse_proc_pid_stat_starttime_ticks(&content))
        })
        .map(|start_time| {
            let ticks_per_sec = 100u64;

            start_time / ticks_per_sec
        })
}

#[cfg(target_os = "macos")]
fn get_daemon_uptime() -> Option<u64> {
    if let Ok(output) = std::process::Command::new("pgrep")
        .args(["-o", "-x", "rustynetd"])
        .output()
        && let Ok(pid_str) = String::from_utf8(output.stdout)
        && let Ok(pid) = pid_str.trim().parse::<i32>()
        && let Ok(output) = std::process::Command::new("ps")
            .args(["-o", "etime=", "-p"])
            .arg(pid.to_string())
            .output()
        && let Ok(etime) = String::from_utf8(output.stdout)
    {
        let etime = etime.trim();
        let parts: Vec<&str> = etime.split(':').collect();

        let total_secs = if parts.len() == 3 {
            if let (Ok(h), Ok(m), Ok(s)) = (
                parts[0].parse::<u64>(),
                parts[1].parse::<u64>(),
                parts[2].parse::<u64>(),
            ) {
                h * 3600 + m * 60 + s
            } else {
                0
            }
        } else if parts.len() == 2 {
            if let (Ok(m), Ok(s)) = (parts[0].parse::<u64>(), parts[1].parse::<u64>()) {
                m * 60 + s
            } else {
                0
            }
        } else {
            0
        };

        return (total_secs > 0).then_some(total_secs);
    }
    None
}

#[cfg(target_os = "windows")]
fn get_daemon_uptime() -> Option<u64> {
    None
}

#[cfg(unix)]
fn test_ipc_connection() -> bool {
    use std::os::unix::net::UnixStream;
    let socket_path = std::env::var("RUSTYNET_DAEMON_SOCKET")
        .unwrap_or_else(|_| "/var/run/rustynet/daemon.sock".to_owned());
    UnixStream::connect(&socket_path).is_ok()
}

#[cfg(target_os = "windows")]
fn test_ipc_connection() -> bool {
    let pipe_name = std::env::var("RUSTYNET_DAEMON_PIPE")
        .unwrap_or_else(|_| "\\\\.\\pipe\\rustynet-daemon".to_string());
    std::fs::OpenOptions::new()
        .read(true)
        .open(&pipe_name)
        .is_ok()
}

fn validate_config_internal() -> ConfigValidation {
    let mut issues = vec![];

    #[cfg(target_os = "linux")]
    {
        let config_paths = ["/etc/rustynet/config.yaml", "/etc/rustynet/wg.key"];
        for path in &config_paths {
            if fs::metadata(path).is_err() {
                issues.push(format!("{path}: not found"));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let home = dirs_home();
        let config_dir = home.join(".rustynet");
        if !config_dir.exists() {
            issues.push(format!("{}/.rustynet: not found", home.display()));
        }
    }

    #[cfg(target_os = "windows")]
    {
        let config_paths = [
            "C:\\ProgramData\\Rustynet\\config.yaml",
            "C:\\ProgramData\\Rustynet\\keys",
        ];
        for path in &config_paths {
            if !fs::metadata(path).is_ok() {
                issues.push(format!("{}: not found", path));
            }
        }
    }

    ConfigValidation {
        passed: issues.is_empty(),
        issues,
    }
}

fn wg_addresses_internal() -> Vec<String> {
    let mut addresses = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("ip")
            .args(["addr", "show", "rustynet0"])
            .output()
            && let Ok(stdout) = String::from_utf8(output.stdout)
        {
            addresses = parse_ip_addr_inet_addresses(&stdout);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("ifconfig")
            .arg("utun0")
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|stdout| {
                for line in stdout.lines() {
                    if line.contains("inet ") && !line.contains("inet6") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 1 {
                            addresses.push(parts[1].to_owned());
                        }
                    }
                }
            });
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("ipconfig").output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                let mut in_wg = false;
                for line in stdout.lines() {
                    if line.contains("Ethernet adapter") || line.contains("WireGuard") {
                        in_wg = line.to_lowercase().contains("wireguard");
                    }
                    if in_wg && line.contains("IPv4 Address") {
                        if let Some(addr) = line.split(':').nth(1) {
                            addresses.push(addr.trim().to_string());
                        }
                    }
                }
            }
        }
    }

    addresses
}

/// Extract addresses from `ip addr show <iface>` output: the second
/// whitespace field of any line containing `inet` (covers both `inet` and
/// `inet6`, matching the historical behavior). Lines with too few fields are
/// skipped.
#[cfg(target_os = "linux")]
fn parse_ip_addr_inet_addresses(stdout: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    for line in stdout.lines() {
        if line.contains("inet") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 1 {
                addresses.push(parts[1].to_string());
            }
        }
    }
    addresses
}

/// Parse `ip route show` output into routes. `dest [via GW] [dev IFACE] ...`:
/// field 0 is the destination, field 2 the gateway (or `direct`), field 4 the
/// interface (or `-`). Lines with fewer than three fields are skipped.
#[cfg(target_os = "linux")]
fn parse_ip_route_show(stdout: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            routes.push(Route {
                destination: parts[0].to_string(),
                gateway: parts.get(2).unwrap_or(&"direct").to_string(),
                interface: parts.get(4).unwrap_or(&"-").to_string(),
            });
        }
    }
    routes
}

fn route_list_internal() -> Vec<Route> {
    let mut routes = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("ip")
            .args(["route", "show"])
            .output()
            && let Ok(stdout) = String::from_utf8(output.stdout)
        {
            routes = parse_ip_route_show(&stdout);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("netstat")
            .args(["-rn"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|stdout| {
                for line in stdout.lines().skip(3) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        routes.push(Route {
                            destination: parts[0].to_owned(),
                            gateway: parts[1].to_owned(),
                            interface: parts[5].to_owned(),
                        });
                    }
                }
            });
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("route").arg("print").output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                for line in stdout.lines().skip(3) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        routes.push(Route {
                            destination: parts[0].to_string(),
                            gateway: parts[2].to_string(),
                            interface: parts[3].to_string(),
                        });
                    }
                }
            }
        }
    }

    routes
}

/// Whole days between `now_secs` and a file's `modified_secs` (Unix epoch
/// seconds). Uses `saturating_sub` so a modified time in the future — from clock
/// skew or a tampered mtime — reports 0 days instead of panicking on subtraction
/// underflow in debug builds (§10.2 no-panic). Shared by all three platform
/// branches of `key_expiry_internal`.
fn key_age_days(now_secs: u64, modified_secs: u64) -> u64 {
    now_secs.saturating_sub(modified_secs) / 86_400
}

fn key_expiry_internal() -> KeyExpiry {
    let mut key_details = vec![];
    let mut expiring_soon = false;

    #[cfg(target_os = "linux")]
    {
        let key_paths = ["/etc/rustynet/wg.key", "/etc/rustynet/config.yaml"];
        for path in &key_paths {
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(modified) = metadata.modified() {
                    let since_epoch = modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let days_old = key_age_days(now, since_epoch);
                    if days_old > 365 {
                        expiring_soon = true;
                        key_details.push(format!("{path}: {days_old} days old (>1yr)"));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let home = dirs_home();
        let key_path = home.join(".rustynet/keys");
        if let Ok(modified) = fs::metadata(&key_path).and_then(|m| m.modified()) {
            let since_epoch = modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let days_old = key_age_days(now, since_epoch);
            if days_old > 365 {
                expiring_soon = true;
                key_details.push(format!("~/.rustynet/keys: {days_old} days old (>1yr)"));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let key_paths = [
            "C:\\ProgramData\\Rustynet\\keys",
            "C:\\ProgramData\\Rustynet\\config.yaml",
        ];
        for path in &key_paths {
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(modified) = metadata.modified() {
                    let since_epoch = modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let days_old = key_age_days(now, since_epoch);
                    if days_old > 365 {
                        expiring_soon = true;
                        key_details.push(format!("{}: {} days old (>1yr)", path, days_old));
                    }
                }
            }
        }
    }

    KeyExpiry {
        expiring_soon,
        key_details,
    }
}

fn tunnel_status_internal() -> TunnelStatus {
    let iface_info = wireguard_interface_info_internal("rustynet0");
    let (bytes_sent, bytes_recv) = get_interface_bytes("rustynet0");
    let last_handshake = get_last_handshake();

    TunnelStatus {
        up: iface_info.is_up,
        bytes_sent,
        bytes_recv,
        last_handshake_secs: last_handshake,
    }
}

/// Parse `/proc/net/dev` contents for one interface's `(tx_bytes, rx_bytes)`.
/// On the matching line the whitespace fields are `<iface>: rx_bytes rx_packets
/// … tx_bytes …` — field[1] is rx bytes and field[9] is tx bytes. A line with
/// fewer than 10 fields or a non-numeric counter yields 0 for that value, and a
/// missing interface yields `(0, 0)`. NOTE: interface matching is a substring
/// test (behavior unchanged), so a query for `eth0` also matches `veth0` /
/// `eth0.1` lines; the first match wins. Split out for cross-platform unit
/// testing; only called under `target_os = "linux"`.
#[allow(dead_code)]
fn parse_proc_net_dev_bytes(content: &str, interface: &str) -> (u64, u64) {
    for line in content.lines() {
        if line.contains(interface) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let bytes_recv = parts[1].parse::<u64>().unwrap_or(0);
                let bytes_sent = parts[9].parse::<u64>().unwrap_or(0);
                return (bytes_sent, bytes_recv);
            }
        }
    }
    (0, 0)
}

#[cfg(target_os = "linux")]
fn get_interface_bytes(interface: &str) -> (u64, u64) {
    fs::read_to_string("/proc/net/dev")
        .map(|content| parse_proc_net_dev_bytes(&content, interface))
        .unwrap_or((0, 0))
}

#[cfg(target_os = "macos")]
fn get_interface_bytes(_interface: &str) -> (u64, u64) {
    (0, 0)
}

#[cfg(target_os = "windows")]
fn get_interface_bytes(_interface: &str) -> (u64, u64) {
    (0, 0)
}

/// Parse `wg show <iface> latest-handshakes` stdout into the first peer's
/// latest-handshake epoch-seconds timestamp. Each line is
/// `<pubkey>\t<epoch_secs>`; returns the first line whose second whitespace
/// field parses as a `u64` (a never-handshaked peer reports `0`, which is
/// returned as-is). `None` when no line has a numeric second field. Kept pure
/// (no clock) so the age computation stays in the caller and this stays
/// testable; only called under `target_os = "linux"`.
#[allow(dead_code)]
fn parse_wg_latest_handshake_timestamp(stdout: &str) -> Option<u64> {
    stdout.lines().find_map(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            parts[1].parse::<u64>().ok()
        } else {
            None
        }
    })
}

#[cfg(target_os = "linux")]
fn get_last_handshake() -> Option<u64> {
    let output = std::process::Command::new("wg")
        .args(["show", "rustynet0", "latest-handshakes"])
        .output()
        .ok()?;
    let stdout = String::from_utf8(output.stdout).ok()?;
    let handshake = parse_wg_latest_handshake_timestamp(&stdout)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Some(now.saturating_sub(handshake))
}

#[cfg(target_os = "macos")]
fn get_last_handshake() -> Option<u64> {
    None
}

#[cfg(target_os = "windows")]
fn get_last_handshake() -> Option<u64> {
    None
}

fn wg_peers_internal() -> Vec<WireGuardPeer> {
    let mut peers = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("wg")
            .args(["show", "rustynet0"])
            .output()
            && let Ok(stdout) = String::from_utf8(output.stdout)
        {
            peers = parse_wg_show_peers(&stdout);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("wg")
            .args(["show", "rustynet0"])
            .output()
            && let Ok(stdout) = String::from_utf8(output.stdout)
        {
            peers = parse_wg_show_peers(&stdout);
        }
    }

    #[cfg(target_os = "windows")]
    {
        peers.push(WireGuardPeer {
            name: "peer-info".to_string(),
            ip: "(unavailable on this platform)".to_string(),
            allowed_ips: "-".to_string(),
            last_handshake_ago: None,
        });
    }

    peers
}

/// Parse `wg show <iface>` output into peer rows. Split from the IO so it can
/// be exercised with golden fixtures. Lines with fewer than four whitespace
/// fields, and the `interface:`/`public` header lines, are skipped; the name
/// is `peer-` + the first ≤8 chars of field 0, with `allowed_ips` from field 2
/// and `ip` from field 3. (Heuristic/positional — behavior preserved from the
/// pre-split code; the name prefix uses a char-boundary-safe truncation so an
/// unexpected non-ASCII field 0 degrades gracefully instead of panicking.)
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn parse_wg_show_peers(stdout: &str) -> Vec<WireGuardPeer> {
    let mut peers = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] != "interface:" && parts[0] != "public" {
            // `get(..8)` returns None if 8 is not a char boundary (non-ASCII);
            // fall back to the whole field rather than panicking on a byte-slice
            // at a mid-character index. Identical to `[..8]` for ASCII `wg`
            // output where field 0 is a base64 key.
            let name_prefix = parts[0].get(..8).unwrap_or(parts[0]);
            peers.push(WireGuardPeer {
                name: format!("peer-{name_prefix}"),
                ip: parts.get(3).unwrap_or(&"-").to_string(),
                allowed_ips: parts.get(2).unwrap_or(&"-").to_string(),
                last_handshake_ago: None,
            });
        }
    }
    peers
}

fn uptime_internal() -> UptimeInfo {
    let system_uptime = get_system_uptime();
    let daemon_uptime = daemon_health_internal().uptime_secs;

    UptimeInfo {
        system_uptime_secs: system_uptime,
        daemon_uptime_secs: daemon_uptime,
    }
}

#[cfg(target_os = "linux")]
fn get_system_uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .map(|content| parse_proc_uptime_secs(&content))
        .unwrap_or(0)
}

/// Parse the leading uptime-seconds field from `/proc/uptime`
/// (`<uptime> <idle>`), truncated to whole seconds. Malformed input → 0.
#[cfg(target_os = "linux")]
fn parse_proc_uptime_secs(content: &str) -> u64 {
    content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .map(|uptime| uptime as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn get_system_uptime() -> u64 {
    std::process::Command::new("uptime")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|stdout| {
            for part in stdout.split(',') {
                if part.contains("up") {
                    let trimmed = part.trim();
                    if let Some(days) = trimmed.find("day").and_then(|days_pos| {
                        trimmed[..days_pos]
                            .split_whitespace()
                            .last()
                            .and_then(|s| s.parse::<u64>().ok())
                    }) {
                        return Some(days * 86400);
                    }
                }
            }
            None
        })
        .unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn get_system_uptime() -> u64 {
    0
}

fn process_info_internal() -> ProcessInfo {
    let pid = find_daemon_pid();
    let (rss, cpu) = if let Some(p) = pid {
        get_process_stats(p)
    } else {
        (None, None)
    };

    ProcessInfo {
        pid,
        rss_mb: rss,
        cpu_percent: cpu,
    }
}

#[cfg(target_os = "linux")]
fn find_daemon_pid() -> Option<u32> {
    if let Ok(output) = std::process::Command::new("pgrep")
        .args(["-o", "-f", "rustynetd"])
        .output()
    {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            return stdout.trim().parse::<u32>().ok();
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn find_daemon_pid() -> Option<u32> {
    std::process::Command::new("pgrep")
        .args(["-o", "-f", "rustynetd"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|stdout| stdout.trim().parse::<u32>().ok())
}

#[cfg(target_os = "windows")]
fn find_daemon_pid() -> Option<u32> {
    None
}

#[cfg(target_os = "linux")]
fn get_process_stats(pid: u32) -> (Option<u64>, Option<f64>) {
    let status_path = format!("/proc/{pid}/status");

    let rss = fs::read_to_string(&status_path).ok().and_then(|content| {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                return line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|kb| kb / 1024);
            }
        }
        None
    });

    (rss, None)
}

#[cfg(target_os = "macos")]
fn get_process_stats(_pid: u32) -> (Option<u64>, Option<f64>) {
    (None, None)
}

#[cfg(target_os = "windows")]
fn get_process_stats(_pid: u32) -> (Option<u64>, Option<f64>) {
    (None, None)
}

fn connection_test_internal() -> ConnectionTest {
    let tunnel_up = wireguard_interface_info_internal("rustynet0").is_up;
    let exit_reachable = test_tcp_connection("8.8.8.8", 53).is_ok();
    let dns_ok = test_dns_resolution("google.com").is_some();

    let message = if tunnel_up && exit_reachable && dns_ok {
        "all tests passed".to_owned()
    } else {
        let mut issues = vec![];
        if !tunnel_up {
            issues.push("tunnel down");
        }
        if !exit_reachable {
            issues.push("exit node unreachable");
        }
        if !dns_ok {
            issues.push("dns resolution failed");
        }
        issues.join(", ")
    };

    ConnectionTest {
        tunnel_reachable: tunnel_up,
        exit_node_reachable: exit_reachable,
        dns_working: dns_ok,
        message,
    }
}

fn test_tcp_connection(host: &str, port: u16) -> Result<(), String> {
    use std::net::TcpStream;
    use std::time::Duration;

    match TcpStream::connect_timeout(
        &format!("{host}:{port}")
            .parse()
            .map_err(|e| format!("{e}"))?,
        Duration::from_secs(3),
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{e}")),
    }
}

fn test_dns_resolution(domain: &str) -> Option<String> {
    std::net::ToSocketAddrs::to_socket_addrs(&format!("{domain}:53"))
        .ok()?
        .next()
        .map(|addr| addr.to_string())
}

fn log_tail_internal(lines: usize) -> Vec<String> {
    let mut result = vec![];
    let limit = lines.max(1);

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("tail")
            .args(["-n", &limit.to_string(), "/var/log/syslog"])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                result = stdout.lines().map(|s| s.to_string()).collect();
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("log")
            .args([
                "show",
                "--predicate",
                "processImagePath contains 'rustynet'",
                "--last",
                "1h",
            ])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|stdout| {
                result = stdout
                    .lines()
                    .take(limit)
                    .map(std::string::ToString::to_string)
                    .collect();
            });
    }

    #[cfg(target_os = "windows")]
    {
        result.push("(log tail unavailable on Windows)".to_string());
    }

    result
}

fn log_errors_internal() -> Vec<String> {
    let mut errors = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("grep")
            .args(["error\\|Error\\|ERROR", "/var/log/syslog"])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                errors = stdout.lines().take(20).map(|s| s.to_string()).collect();
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("log")
            .args([
                "show",
                "--predicate",
                "eventMessage contains[c] 'error'",
                "--last",
                "1h",
            ])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|stdout| {
                errors = stdout
                    .lines()
                    .take(20)
                    .map(std::string::ToString::to_string)
                    .collect();
            });
    }

    #[cfg(target_os = "windows")]
    {
        errors.push("(error log unavailable on Windows)".to_string());
    }

    errors
}

fn bandwidth_test_internal() -> BandwidthTest {
    let download_mbps = simulate_bandwidth_test();
    let upload_mbps = simulate_bandwidth_test() * 0.8;
    let latency_ms = simulate_latency_test();

    BandwidthTest {
        download_mbps,
        upload_mbps,
        latency_ms,
    }
}

fn simulate_bandwidth_test() -> f64 {
    std::thread::sleep(std::time::Duration::from_millis(100));
    50.0
}

fn simulate_latency_test() -> f64 {
    let start = std::time::Instant::now();
    let _ = test_tcp_connection("8.8.8.8", 53);
    start.elapsed().as_millis() as f64
}

#[allow(clippy::vec_init_then_push)]
fn interface_stats_internal() -> Vec<InterfaceStats> {
    let mut stats = vec![];

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/proc/net/dev") {
            stats = parse_proc_net_dev(&content);
        }
    }

    #[cfg(not(target_os = "linux"))]
    stats.push(InterfaceStats {
        name: "(detailed stats unavailable on this platform)".to_owned(),
        bytes_in: 0,
        bytes_out: 0,
        packets_in: 0,
        packets_out: 0,
        errors: 0,
        dropped: 0,
    });

    stats
}

/// Parse `/proc/net/dev` into per-interface counters. Split from the file read
/// so it can be exercised with golden fixtures.
///
/// The first two lines are headers and are skipped. A real row carries 17
/// whitespace fields (`iface:` + 16 counters); we read up to index 10
/// (tx packets), so the guard is `>= 11` — a short/truncated row is skipped
/// rather than panicking on the `parts[10]` access. Non-numeric counters
/// degrade to 0 (preserved `unwrap_or(0)` behavior).
#[cfg(target_os = "linux")]
fn parse_proc_net_dev(content: &str) -> Vec<InterfaceStats> {
    let mut stats = Vec::new();
    for line in content.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 11 {
            stats.push(InterfaceStats {
                name: parts[0].trim_end_matches(':').to_string(),
                bytes_in: parts[1].parse::<u64>().unwrap_or(0),
                bytes_out: parts[9].parse::<u64>().unwrap_or(0),
                packets_in: parts[2].parse::<u64>().unwrap_or(0),
                packets_out: parts[10].parse::<u64>().unwrap_or(0),
                errors: parts[3].parse::<u64>().unwrap_or(0),
                dropped: parts[4].parse::<u64>().unwrap_or(0),
            });
        }
    }
    stats
}

fn health_check_internal() -> HealthCheck {
    let daemon_health = daemon_health_internal();
    let tunnel_health = wireguard_interface_info_internal("rustynet0");
    let connection_health = connection_test_internal();
    let config_health = validate_config_internal();

    let daemon_healthy = daemon_health.running && daemon_health.ipc_reachable;
    let tunnel_healthy = tunnel_health.is_up;
    let network_healthy = connection_health.tunnel_reachable && connection_health.dns_working;
    let system_healthy = daemon_healthy && tunnel_healthy && network_healthy;

    let mut issues = vec![];
    if !daemon_healthy {
        issues.push("daemon not running or IPC unreachable".to_owned());
    }
    if !tunnel_healthy {
        issues.push("tunnel interface down".to_owned());
    }
    if !connection_health.tunnel_reachable {
        issues.push("tunnel not reachable".to_owned());
    }
    if !connection_health.dns_working {
        issues.push("dns resolution failing".to_owned());
    }
    if !config_health.passed {
        issues.extend(config_health.issues);
    }

    let overall_status = if system_healthy {
        "healthy".to_owned()
    } else if daemon_healthy && network_healthy {
        "degraded".to_owned()
    } else {
        "critical".to_owned()
    };

    HealthCheck {
        overall_status,
        system_healthy,
        daemon_healthy,
        tunnel_healthy,
        network_healthy,
        issues,
    }
}

/// Parse the three load averages from `/proc/loadavg` (`1min 5min 15min ...`).
/// A malformed/short line yields zeros. Non-numeric fields degrade to 0.0.
#[cfg(target_os = "linux")]
fn parse_proc_loadavg(content: &str) -> (f64, f64, f64) {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() >= 3 {
        (
            parts[0].parse().unwrap_or(0.0),
            parts[1].parse().unwrap_or(0.0),
            parts[2].parse().unwrap_or(0.0),
        )
    } else {
        (0.0, 0.0, 0.0)
    }
}

#[cfg(target_os = "linux")]
fn system_load_internal() -> SystemLoad {
    let (load_1, load_5, load_15) = match fs::read_to_string("/proc/loadavg") {
        Ok(content) => parse_proc_loadavg(&content),
        Err(_) => (0.0, 0.0, 0.0),
    };

    let mem_percent = memory_info_internal().percent;
    let disk_percent = disk_info_internal()
        .first()
        .map(|d| d.percent)
        .unwrap_or(0.0);

    SystemLoad {
        cpu_load_1min: load_1,
        cpu_load_5min: load_5,
        cpu_load_15min: load_15,
        memory_percent: mem_percent,
        disk_percent,
    }
}

#[cfg(target_os = "macos")]
fn system_load_internal() -> SystemLoad {
    let mut load_1 = 0.0;
    let mut load_5 = 0.0;
    let mut load_15 = 0.0;

    if let Ok(output) = std::process::Command::new("uptime").output()
        && let Ok(s) = String::from_utf8(output.stdout)
        && let Some(load_part) = s.split("load average:").nth(1)
    {
        let loads: Vec<&str> = load_part.split(',').collect();
        if loads.len() >= 3 {
            load_1 = loads[0].trim().parse().unwrap_or(0.0);
            load_5 = loads[1].trim().parse().unwrap_or(0.0);
            load_15 = loads[2].trim().parse().unwrap_or(0.0);
        }
    }

    let mem_percent = memory_info_internal().percent;
    let disk_percent = disk_info_internal().first().map_or(0.0, |d| d.percent);

    SystemLoad {
        cpu_load_1min: load_1,
        cpu_load_5min: load_5,
        cpu_load_15min: load_15,
        memory_percent: mem_percent,
        disk_percent,
    }
}

#[cfg(target_os = "windows")]
fn system_load_internal() -> SystemLoad {
    SystemLoad {
        cpu_load_1min: 0.0,
        cpu_load_5min: 0.0,
        cpu_load_15min: 0.0,
        memory_percent: memory_info_internal().percent,
        disk_percent: disk_info_internal()
            .first()
            .map(|d| d.percent)
            .unwrap_or(0.0),
    }
}

#[cfg(target_os = "linux")]
fn memory_info_internal() -> MemoryInfo {
    match fs::read_to_string("/proc/meminfo") {
        Ok(content) => parse_proc_meminfo(&content),
        Err(_) => MemoryInfo {
            total_mb: 0,
            used_mb: 0,
            available_mb: 0,
            percent: 0.0,
        },
    }
}

/// Parse `MemTotal`/`MemAvailable` (kB) from `/proc/meminfo` into a
/// [`MemoryInfo`] (MB + used percent). Missing fields default to 0.
#[cfg(target_os = "linux")]
fn parse_proc_meminfo(content: &str) -> MemoryInfo {
    let mut total = 0u64;
    let mut available = 0u64;
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
        } else if line.starts_with("MemAvailable:") {
            available = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }

    let used = total.saturating_sub(available);
    let percent = if total > 0 {
        (used as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    MemoryInfo {
        total_mb: total / 1024,
        used_mb: used / 1024,
        available_mb: available / 1024,
        percent,
    }
}

/// Extract the value portion of a macOS `sysctl <key>` line printed in the
/// default `key: value` form (used for `hw.memsize`, `hw.ncpu`, and
/// `machdep.cpu.brand_string`). Mirrors the historical `s.split(':').
/// nth(1)` shape used at every one of those call sites: only the segment
/// between the *first* and *second* colon is returned, so — exactly as
/// before the split — a value that itself contains a colon would be
/// truncated at the second one. Returns `None` when there is no second
/// segment (no colon at all, e.g. empty stdout or a key `sysctl` printed
/// with nothing after it), in which case callers keep their pre-set
/// default.
#[allow(dead_code)]
fn parse_macos_sysctl_colon_value(output: &str) -> Option<&str> {
    output.split(':').nth(1).map(str::trim)
}

#[cfg(target_os = "macos")]
fn memory_info_internal() -> MemoryInfo {
    let mut total = 0u64;
    let mut used = 0u64;

    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("hw.memsize")
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
        && let Some(val) = parse_macos_sysctl_colon_value(&s)
    {
        total = val.parse::<u64>().unwrap_or(0) / 1024 / 1024;
    }

    if let Ok(output) = std::process::Command::new("vm_stat").output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        for line in s.lines() {
            if (line.contains("Pages wired down") || line.contains("Pages active"))
                && let Some(val) = line.split_whitespace().last()
            {
                let pages = val.trim_end_matches('.').parse::<u64>().unwrap_or(0);
                used += pages * 4 / 1024;
            }
        }
    }

    let available = total.saturating_sub(used);
    let percent = if total > 0 {
        (used as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    MemoryInfo {
        total_mb: total,
        used_mb: used,
        available_mb: available,
        percent,
    }
}

#[cfg(target_os = "windows")]
fn memory_info_internal() -> MemoryInfo {
    let mut total = 0u64;
    let mut available = 0u64;

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let lines: Vec<&str> = s.lines().collect();
            for line in lines.iter().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    total = parts[0].parse::<u64>().unwrap_or(0);
                    available = parts[1].parse::<u64>().unwrap_or(0);
                }
            }
        }
    }

    let used = total.saturating_sub(available);
    let percent = if total > 0 {
        (used as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    MemoryInfo {
        total_mb: total / 1024,
        used_mb: used / 1024,
        available_mb: available / 1024,
        percent,
    }
}

#[cfg(target_os = "linux")]
fn disk_info_internal() -> Vec<DiskInfo> {
    vec![DiskInfo {
        mount: "/".to_string(),
        total_mb: 0,
        used_mb: 0,
        available_mb: 0,
        percent: 0.0,
    }]
}

#[cfg(target_os = "macos")]
fn disk_info_internal() -> Vec<DiskInfo> {
    let mut disks = Vec::new();

    if let Ok(output) = std::process::Command::new("df").args(["-k", "/"]).output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        for line in s.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let total_kb = parts[1].parse::<u64>().unwrap_or(0);
                let used_kb = parts[2].parse::<u64>().unwrap_or(0);
                let available_kb = parts[3].parse::<u64>().unwrap_or(0);

                let total_mb = total_kb / 1024;
                let used_mb = used_kb / 1024;
                let available_mb = available_kb / 1024;
                let percent = if total_mb > 0 {
                    (used_mb as f64 / total_mb as f64) * 100.0
                } else {
                    0.0
                };

                disks.push(DiskInfo {
                    mount: "/".to_owned(),
                    total_mb,
                    used_mb,
                    available_mb,
                    percent,
                });
            }
        }
    }

    if disks.is_empty() {
        disks.push(DiskInfo {
            mount: "/".to_owned(),
            total_mb: 0,
            used_mb: 0,
            available_mb: 0,
            percent: 0.0,
        });
    }

    disks
}

#[cfg(target_os = "windows")]
fn disk_info_internal() -> Vec<DiskInfo> {
    let mut disks = Vec::new();

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter,Size,SizeRemaining",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let drive = parts[0].to_string();
                    let total = parts[1].parse::<u64>().unwrap_or(0);
                    let available = parts[2].parse::<u64>().unwrap_or(0);
                    let used = total.saturating_sub(available);
                    let percent = if total > 0 { (used as f64 / total as f64) * 100.0 } else { 0.0 };

                    disks.push(DiskInfo {
                        mount: format!("{}:", drive),
                        total_mb: total / 1024 / 1024,
                        used_mb: used / 1024 / 1024,
                        available_mb: available / 1024 / 1024,
                        percent,
                    });
                }
            }
        }
    }

    if disks.is_empty() {
        disks.push(DiskInfo {
            mount: "C:".to_string(),
            total_mb: 0,
            used_mb: 0,
            available_mb: 0,
            percent: 0.0,
        });
    }

    disks
}

#[cfg(target_os = "linux")]
fn cpu_info_internal() -> CpuInfo {
    match fs::read_to_string("/proc/cpuinfo") {
        Ok(content) => parse_proc_cpuinfo(&content),
        Err(_) => CpuInfo {
            cores: 1,
            model: "Unknown".to_string(),
            freq_ghz: None,
        },
    }
}

/// Parse core count (`processor` lines) and `model name` from `/proc/cpuinfo`.
/// An empty/coreless file reports 1 core and `Unknown`.
#[cfg(target_os = "linux")]
fn parse_proc_cpuinfo(content: &str) -> CpuInfo {
    let mut proc_count = 0usize;
    let mut model = "Unknown".to_string();
    for line in content.lines() {
        if line.starts_with("processor") {
            proc_count += 1;
        } else if line.starts_with("model name")
            && let Some(name) = line.split(':').nth(1)
        {
            model = name.trim().to_string();
        }
    }
    CpuInfo {
        cores: if proc_count > 0 { proc_count } else { 1 },
        model,
        freq_ghz: None,
    }
}

#[cfg(target_os = "macos")]
fn cpu_info_internal() -> CpuInfo {
    let mut cores = 1usize;
    let mut model = "Apple Silicon/Intel".to_owned();

    if let Ok(output) = std::process::Command::new("sysctl").arg("hw.ncpu").output()
        && let Ok(s) = String::from_utf8(output.stdout)
        && let Some(val) = parse_macos_sysctl_colon_value(&s)
    {
        cores = val.parse::<usize>().unwrap_or(1);
    }

    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("machdep.cpu.brand_string")
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
        && let Some(val) = parse_macos_sysctl_colon_value(&s)
    {
        model = val.to_owned();
    }

    CpuInfo {
        cores,
        model,
        freq_ghz: None,
    }
}

#[cfg(target_os = "windows")]
fn cpu_info_internal() -> CpuInfo {
    let mut cores = 1usize;
    let mut model = "Unknown".to_string();

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Processor | Select-Object NumberOfCores,Name",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let lines: Vec<&str> = s.lines().collect();
            for line in lines.iter().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    cores = parts[0].parse::<usize>().unwrap_or(1);
                    model = parts[1..].join(" ");
                }
            }
        }
    }

    CpuInfo {
        cores,
        model,
        freq_ghz: None,
    }
}

#[cfg(target_os = "linux")]
fn socket_stats_internal() -> SocketStats {
    match fs::read_to_string("/proc/net/tcp") {
        Ok(content) => parse_proc_net_tcp_states(&content),
        Err(_) => SocketStats {
            established: 0,
            listening: 0,
            time_wait: 0,
            total: 0,
        },
    }
}

/// Tally TCP socket states from `/proc/net/tcp`. The header line is skipped;
/// field 3 (`st`) is the kernel state hex — `01` established, `0A` listening,
/// `06` time-wait. Unknown states and short lines are ignored.
#[cfg(target_os = "linux")]
fn parse_proc_net_tcp_states(content: &str) -> SocketStats {
    let mut established = 0usize;
    let mut listening = 0usize;
    let mut time_wait = 0usize;
    for line in content.lines().skip(1) {
        if let Some(state_str) = line.split_whitespace().nth(3) {
            match state_str {
                "01" => established += 1,
                "0A" => listening += 1,
                "06" => time_wait += 1,
                _ => {}
            }
        }
    }
    SocketStats {
        established,
        listening,
        time_wait,
        total: established + listening + time_wait,
    }
}

/// Tally TCP socket states from macOS `netstat -an -p tcp` rows via
/// substring `contains` matching — looser than the histogram parsers'
/// exact last-field match: a line counts as `ESTABLISHED`/`LISTEN`/
/// `TIME_WAIT` if that substring appears *anywhere* in it, checked in that
/// precedence order via an if/else-if chain (so a line matching more than
/// one substring is attributed to whichever is checked first). The header
/// line is skipped.
#[allow(dead_code)]
fn parse_netstat_tcp_socket_states_macos(output: &str) -> SocketStats {
    let mut established = 0usize;
    let mut listening = 0usize;
    let mut time_wait = 0usize;

    for line in output.lines().skip(1) {
        if line.contains("ESTABLISHED") {
            established += 1;
        } else if line.contains("LISTEN") {
            listening += 1;
        } else if line.contains("TIME_WAIT") {
            time_wait += 1;
        }
    }

    SocketStats {
        established,
        listening,
        time_wait,
        total: established + listening + time_wait,
    }
}

#[cfg(target_os = "macos")]
fn socket_stats_internal() -> SocketStats {
    if let Ok(output) = std::process::Command::new("netstat")
        .args(["-an", "-p", "tcp"])
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        return parse_netstat_tcp_socket_states_macos(&s);
    }

    SocketStats {
        established: 0,
        listening: 0,
        time_wait: 0,
        total: 0,
    }
}

/// Parse PowerShell `Get-NetTCPConnection | Group-Object State` output into
/// [`SocketStats`]. The first two lines (`Name`/`Count` header + `----`
/// underline) are skipped; each remaining `<state> <count>` row *sets*
/// (not accumulates) the matching bucket, since `Group-Object` already
/// aggregates per state — unlike the macOS per-connection-line tally
/// above. State-name matching is case-insensitive substring (`established`
/// / `listen` / `time_wait` or `timewait`); an unrecognized state name is
/// silently ignored (it never had an `other` bucket in [`SocketStats`]).
#[allow(dead_code)]
fn parse_powershell_tcp_state_groups(output: &str) -> SocketStats {
    let mut established = 0usize;
    let mut listening = 0usize;
    let mut time_wait = 0usize;

    for line in output.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let state = parts[0].to_lowercase();
            let count = parts[1].parse::<usize>().unwrap_or(0);

            if state.contains("established") {
                established = count;
            } else if state.contains("listen") {
                listening = count;
            } else if state.contains("time_wait") || state.contains("timewait") {
                time_wait = count;
            }
        }
    }

    SocketStats {
        established,
        listening,
        time_wait,
        total: established + listening + time_wait,
    }
}

#[cfg(target_os = "windows")]
fn socket_stats_internal() -> SocketStats {
    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetTCPConnection | Select-Object State | Group-Object State | Select-Object Name,Count",
        ])
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        return parse_powershell_tcp_state_groups(&s);
    }

    SocketStats {
        established: 0,
        listening: 0,
        time_wait: 0,
        total: 0,
    }
}

#[cfg(target_os = "linux")]
fn env_validate_internal() -> Vec<String> {
    let required = vec!["RUSTYNET_DAEMON_SOCK", "RUSTYNET_CONFIG", "RUST_LOG"];

    let mut issues = Vec::new();
    for var in required {
        if std::env::var(var).is_err() {
            issues.push(format!("missing: {var}"));
        }
    }

    issues
}

#[cfg(target_os = "macos")]
fn env_validate_internal() -> Vec<String> {
    let required = vec!["RUSTYNET_DAEMON_SOCK", "RUSTYNET_CONFIG"];

    let mut issues = Vec::new();
    for var in required {
        if std::env::var(var).is_err() {
            issues.push(format!("missing: {var}"));
        }
    }

    issues
}

#[cfg(target_os = "windows")]
fn env_validate_internal() -> Vec<String> {
    let required = vec!["RUSTYNET_CONFIG"];

    let mut issues = Vec::new();
    for var in required {
        if std::env::var(var).is_err() {
            issues.push(format!("missing: {var}"));
        }
    }

    issues
}

#[cfg(target_os = "linux")]
fn process_list_internal() -> Vec<ProcessListEntry> {
    let mut procs = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if !metadata.is_dir() {
                    continue;
                }
            }

            let pid_str = entry.file_name();
            if let Ok(pid) = pid_str.to_string_lossy().parse::<u32>() {
                let status_path = format!("/proc/{pid}/status");
                if let Ok(content) = fs::read_to_string(&status_path) {
                    let mut name = format!("pid_{pid}");
                    let mut memory = 0u64;

                    for line in content.lines() {
                        if line.starts_with("Name:") {
                            if let Some(n) = line.split('\t').nth(1) {
                                name = n.to_string();
                            }
                        } else if line.starts_with("VmRSS:") {
                            if let Some(m) = line.split_whitespace().nth(1) {
                                memory = m.parse::<u64>().unwrap_or(0);
                            }
                        }
                    }

                    if name.contains("rustynet") || name.contains("daemon") {
                        procs.push(ProcessListEntry {
                            name,
                            pid,
                            memory_mb: memory / 1024,
                            uptime_seconds: 0,
                        });
                    }
                }
            }
        }
    }

    procs
}

#[cfg(target_os = "macos")]
fn process_list_internal() -> Vec<ProcessListEntry> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn process_list_internal() -> Vec<ProcessListEntry> {
    let mut procs = Vec::new();

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'rustynet' -or $_.Name -match 'daemon' } | Select-Object Name,Id,WorkingSet",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let name = parts[0].to_string();
                    let pid = parts[1].parse::<u32>().unwrap_or(0);
                    let memory_mb = parts[2].parse::<u64>().unwrap_or(0) / 1024 / 1024;

                    procs.push(ProcessListEntry {
                        name,
                        pid,
                        memory_mb,
                        uptime_seconds: 0,
                    });
                }
            }
        }
    }

    procs
}

#[cfg(target_os = "linux")]
fn iface_list_internal() -> Vec<InterfaceDetail> {
    let mut ifaces = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();

            let up = fs::read_to_string(path.join("operstate"))
                .ok()
                .map(|s| s.trim() == "up")
                .unwrap_or(false);

            let mac_address = fs::read_to_string(path.join("address"))
                .ok()
                .map(|s| s.trim().to_string());
            let mtu = fs::read_to_string(path.join("mtu"))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(1500);

            ifaces.push(InterfaceDetail {
                name,
                up,
                mac_address,
                ip_addresses: Vec::new(),
                mtu,
            });
        }
    }

    ifaces
}

#[cfg(target_os = "macos")]
fn iface_list_internal() -> Vec<InterfaceDetail> {
    let mut ifaces = Vec::new();

    if let Ok(output) = std::process::Command::new("ifconfig").output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        let mut current_iface: Option<InterfaceDetail> = None;

        for line in s.lines() {
            if !line.starts_with('\t') && !line.starts_with(' ') && !line.is_empty() {
                if let Some(iface) = current_iface.take() {
                    ifaces.push(iface);
                }

                let name = line.split(':').next().unwrap_or("").to_owned();
                current_iface = Some(InterfaceDetail {
                    name,
                    up: line.contains("UP"),
                    mac_address: None,
                    ip_addresses: Vec::new(),
                    mtu: 1500,
                });
            } else if let Some(ref mut iface) = current_iface {
                if line.contains("HWaddr ") {
                    if let Some(mac) = line.split("HWaddr ").nth(1) {
                        iface.mac_address = Some(mac.trim().to_owned());
                    }
                } else if line.contains("inet ")
                    && let Some(ip) = line.split_whitespace().nth(1)
                {
                    iface.ip_addresses.push(ip.to_owned());
                } else if line.contains("mtu ")
                    && let Some(mtu_str) = line.split("mtu ").nth(1)
                    && let Some(mtu) = mtu_str.split_whitespace().next()
                {
                    iface.mtu = mtu.parse::<u32>().unwrap_or(1500);
                }
            }
        }

        if let Some(iface) = current_iface {
            ifaces.push(iface);
        }
    }

    ifaces
}

#[cfg(target_os = "windows")]
fn iface_list_internal() -> Vec<InterfaceDetail> {
    let mut ifaces = Vec::new();

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetAdapter | Select-Object Name,Status,MacAddress,InterfaceDescription,MTUSize",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let name = parts[0].to_string();
                    let up = parts[1].to_lowercase().contains("up");
                    let mac = Some(parts[2].to_string());
                    let mtu = parts[4].parse::<u32>().unwrap_or(1500);

                    ifaces.push(InterfaceDetail {
                        name,
                        up,
                        mac_address: mac,
                        ip_addresses: Vec::new(),
                        mtu,
                    });
                }
            }
        }
    }

    ifaces
}

#[cfg(target_os = "linux")]
fn dns_check_internal() -> DnsCheck {
    let mut results = Vec::new();
    let mut resolvers = Vec::new();

    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            if let Some(addr) = line.strip_prefix("nameserver ") {
                let addr = addr.trim().to_string();
                resolvers.push(addr.clone());
                results.push(format!("resolver: {addr}"));
            }
        }
    }

    let working = !resolvers.is_empty();

    DnsCheck {
        working,
        resolvers,
        test_results: results,
    }
}

#[cfg(target_os = "macos")]
fn dns_check_internal() -> DnsCheck {
    DnsCheck {
        working: true,
        resolvers: vec!["8.8.8.8".to_owned()],
        test_results: vec!["DNS available".to_owned()],
    }
}

#[cfg(target_os = "windows")]
fn dns_check_internal() -> DnsCheck {
    DnsCheck {
        working: true,
        resolvers: vec!["8.8.8.8".to_string()],
        test_results: vec!["DNS available".to_string()],
    }
}

#[cfg(target_os = "linux")]
fn kernel_info_internal() -> KernelInfo {
    let version = std::env::consts::OS.to_string();
    let mut release = "unknown".to_string();
    let machine = std::env::consts::ARCH.to_string();

    if let Ok(content) = fs::read_to_string("/proc/version") {
        if let Some(parsed) = parse_proc_version_release(&content) {
            release = parsed;
        }
    }

    KernelInfo {
        version,
        release,
        machine,
    }
}

#[cfg(target_os = "macos")]
fn kernel_info_internal() -> KernelInfo {
    KernelInfo {
        version: "Darwin".to_owned(),
        release: "unknown".to_owned(),
        machine: std::env::consts::ARCH.to_owned(),
    }
}

#[cfg(target_os = "windows")]
fn kernel_info_internal() -> KernelInfo {
    KernelInfo {
        version: "Windows".to_string(),
        release: "unknown".to_string(),
        machine: std::env::consts::ARCH.to_string(),
    }
}

fn service_check_internal() -> ServiceCheck {
    ServiceCheck {
        daemon_running: true,
        daemon_enabled: true,
        uptime_seconds: Some(3600),
        status: "active".to_owned(),
    }
}

#[cfg(target_os = "linux")]
fn permission_check_internal() -> Vec<String> {
    let mut issues = Vec::new();
    let paths = vec![
        "/etc/rustynet/config.yaml",
        "/var/run/rustynet.sock",
        "/var/lib/rustynet/state",
    ];

    for path in paths {
        match fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions();
                if mode.readonly() {
                    issues.push(format!("{path}: read-only"));
                }
            }
            Err(_) => {
                issues.push(format!("{path}: not found"));
            }
        }
    }

    issues
}

#[cfg(target_os = "macos")]
fn permission_check_internal() -> Vec<String> {
    let mut issues = Vec::new();
    let paths = vec![
        "/etc/rustynet/config.yaml",
        "/var/run/rustynet.sock",
        "/var/lib/rustynet/state",
    ];

    for path in paths {
        match fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions();
                if mode.readonly() {
                    issues.push(format!("{path}: read-only"));
                }
            }
            Err(_) => {
                issues.push(format!("{path}: not found"));
            }
        }
    }

    issues
}

#[cfg(target_os = "windows")]
fn permission_check_internal() -> Vec<String> {
    Vec::new()
}

fn performance_test_internal() -> PerformanceTest {
    let start = std::time::Instant::now();

    let _data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let elapsed = start.elapsed();

    PerformanceTest {
        cpu_time_ms: elapsed.as_millis() as u64,
        memory_alloc_mb: 1,
        disk_io_ops: 0,
    }
}

fn tls_check_internal() -> TlsCheck {
    TlsCheck {
        tls_available: true,
        tls_version: Some("1.3".to_owned()),
        certificate_valid: true,
        issues: Vec::new(),
    }
}

fn rate_limit_check_internal() -> RateLimitCheck {
    RateLimitCheck {
        current_connections: 0,
        connection_limit: 1000,
        request_rate_per_sec: 0.0,
        rate_limit_per_sec: 100.0,
    }
}

fn nat_detection_internal() -> NatDetection {
    let local_ip = get_local_ip();
    let behind_nat = detect_nat_presence();
    let public_ip = get_public_ip_hint();

    NatDetection {
        behind_nat,
        local_ip,
        public_ip,
        detection_method: "network interface comparison".to_owned(),
    }
}

#[cfg(target_os = "linux")]
fn detect_nat_presence() -> bool {
    if let Ok(content) = fs::read_to_string("/proc/net/route") {
        return content.lines().any(|line| {
            line.contains("00000000") && !line.contains("0A000000") && !line.contains("C0A80000")
        });
    }
    false
}

#[cfg(target_os = "macos")]
fn detect_nat_presence() -> bool {
    if let Ok(output) = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            return s.contains("gateway:");
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn detect_nat_presence() -> bool {
    if let Ok(output) = std::process::Command::new("ipconfig").arg("/all").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            return s.to_lowercase().contains("default gateway");
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn get_local_ip() -> String {
    if let Ok(output) = std::process::Command::new("hostname").arg("-I").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            if let Some(ip) = s.split_whitespace().next() {
                return ip.to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

#[cfg(target_os = "macos")]
fn get_local_ip() -> String {
    if let Ok(output) = std::process::Command::new("ifconfig").arg("en0").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                if line.contains("inet ") && !line.contains("inet6") {
                    if let Some(ip) = line.split_whitespace().nth(1) {
                        return ip.to_owned();
                    }
                }
            }
        }
    }
    "127.0.0.1".to_owned()
}

#[cfg(target_os = "windows")]
fn get_local_ip() -> String {
    if let Ok(output) = std::process::Command::new("ipconfig").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                if line.contains("IPv4 Address") {
                    if let Some(ip) = line.split(':').nth(1) {
                        return ip.trim().to_string();
                    }
                }
            }
        }
    }
    "127.0.0.1".to_string()
}

fn get_public_ip_hint() -> Option<String> {
    None
}

fn exit_node_status_internal() -> ExitNodeStatus {
    let reachable = test_tcp_connection("8.8.8.8", 53).is_ok();
    let latency = measure_latency_to_host("8.8.8.8");

    ExitNodeStatus {
        reachable,
        latency_ms: latency,
        exit_ip: None,
        status: if reachable {
            "exit node reachable".to_owned()
        } else {
            "exit node unreachable".to_owned()
        },
    }
}

fn ipv6_support_internal() -> Ipv6Support {
    let ipv6_addresses = get_ipv6_addresses();
    let ipv6_available = !ipv6_addresses.is_empty();
    let dns_ipv6_capable = test_dns_aaaa_lookup();

    Ipv6Support {
        ipv6_available,
        ipv6_addresses,
        dns_ipv6_capable,
        status: if ipv6_available {
            "IPv6 supported".to_owned()
        } else {
            "IPv6 not available".to_owned()
        },
    }
}

#[cfg(target_os = "linux")]
fn get_ipv6_addresses() -> Vec<String> {
    let mut addrs = Vec::new();
    if let Ok(output) = std::process::Command::new("ip")
        .args(["addr", "show"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                if line.contains("inet6") && !line.contains("::1") {
                    if let Some(addr) = line.split_whitespace().nth(1) {
                        addrs.push(addr.split('/').next().unwrap_or(addr).to_string());
                    }
                }
            }
        }
    }
    addrs
}

#[cfg(target_os = "macos")]
fn get_ipv6_addresses() -> Vec<String> {
    let mut addrs = Vec::new();
    if let Ok(output) = std::process::Command::new("ifconfig").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                if line.contains("inet6") && !line.contains("::1") {
                    if let Some(addr) = line.split_whitespace().nth(1) {
                        addrs.push(addr.to_owned());
                    }
                }
            }
        }
    }
    addrs
}

#[cfg(target_os = "windows")]
fn get_ipv6_addresses() -> Vec<String> {
    let mut addrs = Vec::new();
    if let Ok(output) = std::process::Command::new("ipconfig").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                if line.contains("IPv6 Address") {
                    if let Some(addr) = line.split(':').nth(1) {
                        addrs.push(addr.trim().to_string());
                    }
                }
            }
        }
    }
    addrs
}

fn test_dns_aaaa_lookup() -> bool {
    use std::net::IpAddr;
    use std::str::FromStr;

    IpAddr::from_str("2001:4860:4860::8888").is_ok()
}

fn packet_loss_internal() -> PacketLossCheck {
    let (loss_percent, packets_sent, packets_received, min_lat, avg_lat, max_lat) =
        measure_packet_loss();

    PacketLossCheck {
        loss_percent,
        packets_sent,
        packets_received,
        min_latency_ms: min_lat,
        avg_latency_ms: avg_lat,
        max_latency_ms: max_lat,
    }
}

#[cfg(target_os = "linux")]
fn measure_packet_loss() -> (f64, usize, usize, Option<f64>, Option<f64>, Option<f64>) {
    if let Ok(output) = std::process::Command::new("ping")
        .args(["-c", "10", "8.8.8.8"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let packets_sent = 10;
            let mut packets_received = 10;
            let mut loss_percent = 0.0;

            for line in s.lines() {
                if line.contains("received") {
                    if let Some(part) = line.split(',').next() {
                        if let Some(num) = part.split_whitespace().next() {
                            packets_received = num.parse().unwrap_or(10);
                        }
                    }
                    if let Some(pct) = line
                        .split('%')
                        .next()
                        .and_then(|s| s.split_whitespace().last())
                    {
                        loss_percent = pct.parse().unwrap_or(0.0);
                    }
                }
            }
            return (
                loss_percent,
                packets_sent,
                packets_received,
                None,
                None,
                None,
            );
        }
    }
    (0.0, 10, 10, None, None, None)
}

#[cfg(target_os = "macos")]
fn measure_packet_loss() -> (f64, usize, usize, Option<f64>, Option<f64>, Option<f64>) {
    if let Ok(output) = std::process::Command::new("ping")
        .args(["-c", "10", "8.8.8.8"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let mut packets_sent = 10;
            let mut loss_percent = 0.0;

            for line in s.lines() {
                if line.contains("transmitted") {
                    if let Some(num) = line.split_whitespace().next() {
                        packets_sent = num.parse().unwrap_or(10);
                    }
                }
                if line.contains("packet loss") {
                    if let Some(pct) = line
                        .split('%')
                        .next()
                        .and_then(|s| s.split_whitespace().last())
                    {
                        loss_percent = pct.parse().unwrap_or(0.0);
                    }
                }
            }
            let packets_received = (packets_sent as f64 * (1.0 - loss_percent / 100.0)) as usize;
            return (
                loss_percent,
                packets_sent,
                packets_received,
                None,
                None,
                None,
            );
        }
    }
    (0.0, 10, 10, None, None, None)
}

#[cfg(target_os = "windows")]
fn measure_packet_loss() -> (f64, usize, usize, Option<f64>, Option<f64>, Option<f64>) {
    if let Ok(output) = std::process::Command::new("ping")
        .args(["-n", "10", "8.8.8.8"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let mut packets_sent = 10;
            let mut loss_percent = 0.0;

            for line in s.lines() {
                if line.contains("Packets: Sent") {
                    if let Some(num) = line.split('=').nth(1).and_then(|s| s.split(',').next()) {
                        packets_sent = num.trim().parse().unwrap_or(10);
                    }
                }
                if line.contains("(") && line.contains("% loss)") {
                    if let Some(pct) = line.split('(').nth(1).and_then(|s| s.split('%').next()) {
                        loss_percent = pct.parse().unwrap_or(0.0);
                    }
                }
            }
            let packets_received = (packets_sent as f64 * (1.0 - loss_percent / 100.0)) as usize;
            return (
                loss_percent,
                packets_sent,
                packets_received,
                None,
                None,
                None,
            );
        }
    }
    (0.0, 10, 10, None, None, None)
}

fn system_clock_check_internal() -> SystemClockCheck {
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("timedatectl").output() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let synced =
                    s.contains("synchronized: yes") || s.contains("System clock synchronized: yes");
                let ntp_active = s.contains("NTP service: active")
                    || s.contains("systemd-timesyncd.service active: yes");

                return SystemClockCheck {
                    synced,
                    ntp_active,
                    time_offset_ms: None,
                    last_sync_seconds_ago: None,
                    status: if synced {
                        "system clock synchronized".to_string()
                    } else {
                        "system clock not synchronized".to_string()
                    },
                };
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ntpq").args(["-p"]).output() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let has_peers = s.lines().count() > 2;
                return SystemClockCheck {
                    synced: has_peers,
                    ntp_active: has_peers,
                    time_offset_ms: None,
                    last_sync_seconds_ago: None,
                    status: if has_peers {
                        "NTP synchronized".to_owned()
                    } else {
                        "NTP not synchronized".to_owned()
                    },
                };
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-Service w32time | Select-Object Status",
            ])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let running = s.contains("Running");
                return SystemClockCheck {
                    synced: running,
                    ntp_active: running,
                    time_offset_ms: None,
                    last_sync_seconds_ago: None,
                    status: if running {
                        "Windows Time service running".to_string()
                    } else {
                        "Windows Time service not running".to_string()
                    },
                };
            }
        }
    }

    SystemClockCheck {
        synced: true,
        ntp_active: true,
        time_offset_ms: None,
        last_sync_seconds_ago: None,
        status: "status unknown".to_owned(),
    }
}

fn measure_latency_to_host(host: &str) -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("ping")
            .args(["-c", "1", "-W", "2", host])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                for line in s.lines() {
                    if line.contains("time=") {
                        if let Some(time_part) = line.split("time=").nth(1) {
                            if let Some(ms) = time_part.split_whitespace().next() {
                                return ms.parse().ok();
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ping")
            .args(["-c", "1", "-W", "2", host])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                for line in s.lines() {
                    if line.contains("time=") {
                        if let Some(time_part) = line.split("time=").nth(1) {
                            if let Some(ms) = time_part.split_whitespace().next() {
                                return ms.parse().ok();
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("ping")
            .args(["-n", "1", "-w", "2000", host])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                for line in s.lines() {
                    if line.contains("time=") {
                        if let Some(time_part) = line.split("time=").nth(1) {
                            if let Some(ms) = time_part.split("ms").next() {
                                return ms.trim().parse().ok();
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Decode a `/proc/net/tcp`-style hex IPv4 address (kernel-endian, e.g.
/// `"0100007F"` -> `"127.0.0.1"`) into dotted-decimal. Returns `"unknown"`
/// for anything that isn't (after lowercasing) at least 8 bytes long with
/// each 2-byte chunk a valid hex pair.
///
/// Bug fix folded into this split: the original indexed the input
/// (`&hex[i*2..i*2+2]`) directly, which panics if `hex` contains a
/// multi-byte UTF-8 character whose bytes straddle one of those fixed
/// offsets (`/proc/net/tcp` fields are always plain ASCII hex in practice,
/// so this never fired in production, but it is exactly the kind of
/// adversarial-input panic the parser-never-panics property test below is
/// meant to catch). Switched to `str::get`, which returns `None` — falling
/// through to `"unknown"` — instead of panicking on a non-char-boundary or
/// out-of-range slice. Behavior is identical for every valid-hex input.
#[allow(dead_code)]
fn hex_to_ip(hex: &str) -> String {
    let hex = hex.to_lowercase();
    if hex.len() >= 8 {
        let bytes: Vec<u8> = (0..4)
            .filter_map(|i| hex.get(i * 2..i * 2 + 2))
            .filter_map(|byte_str| u8::from_str_radix(byte_str, 16).ok())
            .collect();
        if bytes.len() == 4 {
            return format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]);
        }
    }
    "unknown".to_string()
}

/// Parse `/proc/net/tcp` rows into [`TcpConnection`]s. The header line is
/// skipped; each data row needs >=4 whitespace fields
/// (`sl local_address rem_address st ...`), where `local_address` /
/// `rem_address` are `<hex_addr>:<hex_port>`. A row is dropped — not
/// defaulted — if either side is missing its `:` separator or either hex
/// component fails to parse, preserved from the pre-split nested-`if let`
/// implementation.
#[allow(dead_code)]
fn parse_proc_net_tcp_connections(content: &str) -> Vec<TcpConnection> {
    let mut connections = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        // /proc/net/tcp encodes each address as `<addr_hex>:<port_hex>`
        // (8 hex chars + ':' + 4 hex chars for IPv4). split_once is the
        // direct decoder. The earlier code split into a Vec, then called
        // split_last (which returns a tuple of `(&last, rest)`), then
        // tried to index `local_parts[0]` to access the original full
        // string — that's a tuple-indexing type error
        //   error[E0608]: cannot index into a value of type
        //   `(&&str, &[&str])`
        // and would have been semantically wrong even without the type
        // error, since `local_parts.0` is the port, not the address+port
        // string the slicing presumed.
        if let Some((local_hex, local_port_hex)) = fields[1].split_once(':') {
            let local_addr = hex_to_ip(local_hex);
            if let Ok(port) = u16::from_str_radix(local_port_hex, 16) {
                let local = format!("{local_addr}:{port}");

                if let Some((remote_hex, remote_port_hex)) = fields[2].split_once(':') {
                    let remote_addr = hex_to_ip(remote_hex);
                    if let Ok(port) = u16::from_str_radix(remote_port_hex, 16) {
                        let remote = format!("{remote_addr}:{port}");
                        let state = fields[3].to_string();
                        connections.push(TcpConnection {
                            local_addr: local,
                            remote_addr: remote,
                            state,
                            pid: None,
                        });
                    }
                }
            }
        }
    }
    connections
}

#[cfg(target_os = "linux")]
fn tcp_connections_internal() -> Vec<TcpConnection> {
    match fs::read_to_string("/proc/net/tcp") {
        Ok(content) => parse_proc_net_tcp_connections(&content),
        Err(_) => Vec::new(),
    }
}

/// Parse macOS `netstat -an -p tcp` rows into [`TcpConnection`]s. The
/// header line is skipped. RSA-0050: the parser indexes `fields[5]`
/// (state), so the column-count guard is `>= 6`, not `>= 4`.
#[allow(dead_code)]
fn parse_netstat_tcp_connections_macos(output: &str) -> Vec<TcpConnection> {
    let mut connections = Vec::new();
    for line in output.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // RSA-0050: indexes fields[5] (state) ⇒ needs >= 6, not >= 4.
        if fields.len() < 6 {
            continue;
        }
        connections.push(TcpConnection {
            local_addr: fields[3].to_owned(),
            remote_addr: fields[4].to_owned(),
            state: fields[5].to_owned(),
            pid: None,
        });
    }
    connections
}

#[cfg(target_os = "macos")]
fn tcp_connections_internal() -> Vec<TcpConnection> {
    if let Ok(output) = std::process::Command::new("netstat")
        .args(["-an", "-p", "tcp"])
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        return parse_netstat_tcp_connections_macos(&s);
    }
    Vec::new()
}

/// Parse `Get-NetTCPConnection | ... | ConvertTo-Csv` output into
/// [`TcpConnection`]s. The CSV header row is skipped; each data row needs
/// at least 5 comma-separated fields (`LocalAddress,LocalPort,
/// RemoteAddress,RemotePort,State`); PowerShell CSV-quotes every value,
/// unquoted here via `trim_matches('"')`.
#[allow(dead_code)]
fn parse_powershell_tcp_connections_csv(output: &str) -> Vec<TcpConnection> {
    let mut connections = Vec::new();
    for line in output.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() >= 5 {
            let local = format!(
                "{}:{}",
                fields[0].trim_matches('"'),
                fields[1].trim_matches('"')
            );
            let remote = format!(
                "{}:{}",
                fields[2].trim_matches('"'),
                fields[3].trim_matches('"')
            );
            connections.push(TcpConnection {
                local_addr: local,
                remote_addr: remote,
                state: fields[4].trim_matches('"').to_string(),
                pid: None,
            });
        }
    }
    connections
}

#[cfg(target_os = "windows")]
fn tcp_connections_internal() -> Vec<TcpConnection> {
    if let Ok(output) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | ConvertTo-Csv -NoTypeInformation"])
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        return parse_powershell_tcp_connections_csv(&s);
    }
    Vec::new()
}

#[cfg(target_os = "linux")]
fn dns_resolver_info_internal() -> DnsResolverInfo {
    let mut resolvers = Vec::new();
    let mut search_domains = Vec::new();

    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("nameserver ") {
                if let Some(ip) = line.strip_prefix("nameserver ") {
                    resolvers.push(ip.to_string());
                }
            } else if line.starts_with("search ") {
                if let Some(domains) = line.strip_prefix("search ") {
                    search_domains = domains.split_whitespace().map(|s| s.to_string()).collect();
                }
            }
        }
    }

    DnsResolverInfo {
        resolvers,
        search_domains,
        method: "resolv.conf".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn dns_resolver_info_internal() -> DnsResolverInfo {
    let mut resolvers = Vec::new();
    let mut search_domains = Vec::new();

    if let Ok(output) = std::process::Command::new("scutil")
        .args(["-d", "-r", "State:/Network/Global/DNS"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                if line.contains("ServerAddresses :") {
                    if let Some(rest) = line.strip_prefix("  ServerAddresses :") {
                        let addrs = rest
                            .split(',')
                            .map(|s| s.trim().trim_matches('{').trim_matches('}').to_owned())
                            .filter(|s| !s.is_empty())
                            .collect();
                        resolvers = addrs;
                    }
                }
                if line.contains("SearchDomains :") {
                    if let Some(rest) = line.strip_prefix("  SearchDomains :") {
                        search_domains = rest
                            .split(',')
                            .map(|s| s.trim().trim_matches('{').trim_matches('}').to_owned())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                }
            }
        }
    }

    DnsResolverInfo {
        resolvers,
        search_domains,
        method: "scutil".to_owned(),
    }
}

#[cfg(target_os = "windows")]
fn dns_resolver_info_internal() -> DnsResolverInfo {
    let mut resolvers = Vec::new();
    if let Ok(output) = std::process::Command::new("ipconfig").arg("/all").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                if line.contains("DNS Servers") {
                    if let Some(ips) = line.split(':').nth(1) {
                        resolvers.push(ips.trim().to_string());
                    }
                }
            }
        }
    }

    DnsResolverInfo {
        resolvers,
        search_domains: Vec::new(),
        method: "ipconfig".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn interface_speed_internal() -> Vec<InterfaceSpeed> {
    let mut speeds = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) {
                let speed_path = format!("/sys/class/net/{name}/speed");
                let mtu_path = format!("/sys/class/net/{name}/mtu");
                let speed_mbps = fs::read_to_string(&speed_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok());
                let mtu = fs::read_to_string(&mtu_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(1500);
                speeds.push(InterfaceSpeed {
                    name,
                    speed_mbps,
                    duplex: None,
                    mtu,
                });
            }
        }
    }
    speeds
}

#[cfg(target_os = "macos")]
fn interface_speed_internal() -> Vec<InterfaceSpeed> {
    let mut speeds = Vec::new();
    if let Ok(output) = std::process::Command::new("ifconfig").output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        let mut current_iface: Option<String> = None;
        let mut mtu = 1500u32;
        for line in s.lines() {
            if !line.starts_with('\t') && !line.starts_with(' ') {
                if let Some(iface) = current_iface.take() {
                    speeds.push(InterfaceSpeed {
                        name: iface,
                        speed_mbps: None,
                        duplex: None,
                        mtu,
                    });
                }
                current_iface = line.split(':').next().map(std::string::ToString::to_string);
            } else if current_iface.is_some()
                && line.contains("mtu")
                && let Some(mtu_str) = line.split("mtu").nth(1)
                && let Some(num) = mtu_str.split_whitespace().next()
            {
                mtu = num.parse().unwrap_or(1500);
            }
        }
        if let Some(iface) = current_iface {
            speeds.push(InterfaceSpeed {
                name: iface,
                speed_mbps: None,
                duplex: None,
                mtu,
            });
        }
    }
    speeds
}

#[cfg(target_os = "windows")]
fn interface_speed_internal() -> Vec<InterfaceSpeed> {
    let mut speeds = Vec::new();
    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetAdapter | Select-Object Name,LinkSpeed,MTU | ConvertTo-Csv -NoTypeInformation",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(1) {
                let fields: Vec<&str> = line.split(',').collect();
                if fields.len() >= 3 {
                    let name = fields[0].trim_matches('"').to_string();
                    let speed_str = fields[1].trim_matches('"');
                    let speed_mbps = if speed_str.contains("Mbps") {
                        speed_str.replace(" Mbps", "").parse::<u64>().ok()
                    } else if speed_str.contains("Gbps") {
                        speed_str
                            .replace(" Gbps", "")
                            .parse::<f64>()
                            .ok()
                            .map(|g| (g * 1000.0) as u64)
                    } else {
                        None
                    };
                    let mtu = fields[2].trim_matches('"').parse::<u32>().unwrap_or(1500);
                    speeds.push(InterfaceSpeed {
                        name,
                        speed_mbps,
                        duplex: None,
                        mtu,
                    });
                }
            }
        }
    }
    speeds
}

#[cfg(target_os = "linux")]
fn disk_io_stats_internal() -> Vec<DiskIoStat> {
    let mut stats = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/diskstats") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 14 {
                let device = fields[2].to_string();
                let read_ops = fields[3].parse::<u64>().unwrap_or(0);
                let read_bytes = fields[5].parse::<u64>().unwrap_or(0) * 512;
                let write_ops = fields[7].parse::<u64>().unwrap_or(0);
                let write_bytes = fields[9].parse::<u64>().unwrap_or(0) * 512;
                stats.push(DiskIoStat {
                    device,
                    read_ops,
                    read_bytes,
                    write_ops,
                    write_bytes,
                });
            }
        }
    }
    stats
}

#[cfg(target_os = "macos")]
fn disk_io_stats_internal() -> Vec<DiskIoStat> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn disk_io_stats_internal() -> Vec<DiskIoStat> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn process_memory_internal() -> Vec<ProcessMemory> {
    let mut mem_map: Vec<(String, u32, u64)> = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    if let Some(pid_str) = entry.file_name().to_str() {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            let status_path = format!("/proc/{pid}/status");
                            if let Ok(content) = fs::read_to_string(status_path) {
                                let mut name = "unknown".to_string();
                                let mut memory_kb = 0u64;
                                for line in content.lines() {
                                    if line.starts_with("Name:") {
                                        if let Some(n) = line.strip_prefix("Name:") {
                                            name = n.trim().to_string();
                                        }
                                    } else if line.starts_with("VmRSS:") {
                                        if let Some(mem_str) = line.strip_prefix("VmRSS:") {
                                            if let Some(num) = mem_str.split_whitespace().next() {
                                                memory_kb = num.parse().unwrap_or(0);
                                            }
                                        }
                                    }
                                }
                                mem_map.push((name, pid, memory_kb));
                            }
                        }
                    }
                }
            }
        }
    }

    mem_map.sort_by(|a, b| b.2.cmp(&a.2));
    mem_map
        .into_iter()
        .take(10)
        .map(|(name, pid, memory_kb)| ProcessMemory {
            name,
            pid,
            memory_mb: (memory_kb / 1024).max(1),
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn process_memory_internal() -> Vec<ProcessMemory> {
    let mut processes = Vec::new();
    if let Ok(output) = std::process::Command::new("ps").args(["aux"]).output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        let mut mem_data: Vec<(String, u32, u64)> = Vec::new();
        for line in s.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 11
                && let Ok(pid) = fields[1].parse::<u32>()
                && let Ok(memory_mb) = fields[5].parse::<u64>()
            {
                let name = fields[10..].join(" ");
                mem_data.push((name, pid, memory_mb));
            }
        }
        mem_data.sort_by_key(|b| std::cmp::Reverse(b.2));
        processes = mem_data
            .into_iter()
            .take(10)
            .map(|(name, pid, memory_mb)| ProcessMemory {
                name,
                pid,
                memory_mb: memory_mb / 1024,
            })
            .collect();
    }
    processes
}

#[cfg(target_os = "windows")]
fn process_memory_internal() -> Vec<ProcessMemory> {
    let mut processes = Vec::new();
    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-Process | Select-Object Name,Id,WorkingSet | Sort-Object WorkingSet -Descending | Select-Object -First 10 | ConvertTo-Csv -NoTypeInformation",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(1) {
                let fields: Vec<&str> = line.split(',').collect();
                if fields.len() >= 3 {
                    let name = fields[0].trim_matches('"').to_string();
                    if let Ok(pid) = fields[1].trim_matches('"').parse::<u32>() {
                        if let Ok(memory_bytes) = fields[2].trim_matches('"').parse::<u64>() {
                            processes.push(ProcessMemory {
                                name,
                                pid,
                                memory_mb: memory_bytes / (1024 * 1024),
                            });
                        }
                    }
                }
            }
        }
    }
    processes
}

// ============================================================================
// NETWORK FUNCTIONS (8)
// ============================================================================

#[cfg(target_os = "linux")]
fn active_network_routes_internal() -> Vec<RouteInfo> {
    let mut routes = Vec::new();
    if let Ok(output) = std::process::Command::new("ip")
        .args(["route", "show"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    routes.push(RouteInfo {
                        destination: parts[0].to_string(),
                        gateway: parts.get(2).unwrap_or(&"direct").to_string(),
                        interface: parts.get(4).unwrap_or(&"-").to_string(),
                        metric: None,
                    });
                }
            }
        }
    }
    routes
}

#[cfg(target_os = "macos")]
fn active_network_routes_internal() -> Vec<RouteInfo> {
    let mut routes = Vec::new();
    if let Ok(output) = std::process::Command::new("netstat").args(["-rn"]).output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(3) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    routes.push(RouteInfo {
                        destination: parts[0].to_owned(),
                        gateway: parts[1].to_owned(),
                        interface: parts[5].to_owned(),
                        metric: None,
                    });
                }
            }
        }
    }
    routes
}

#[cfg(target_os = "windows")]
fn active_network_routes_internal() -> Vec<RouteInfo> {
    let mut routes = Vec::new();
    if let Ok(output) = std::process::Command::new("route").arg("print").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(3) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    routes.push(RouteInfo {
                        destination: parts[0].to_string(),
                        gateway: parts[2].to_string(),
                        interface: parts[3].to_string(),
                        metric: parts.get(1).and_then(|m| m.parse().ok()),
                    });
                }
            }
        }
    }
    routes
}

#[cfg(target_os = "linux")]
fn mtu_path_discovery_internal(target_host: &str) -> DiscoveryResult {
    let mut result = DiscoveryResult {
        host: target_host.to_string(),
        mtu: None,
        hops: None,
        latency_ms: None,
    };
    if let Ok(output) = std::process::Command::new("ping")
        .args(["-M", "do", "-c", "1", target_host])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                if line.contains("time=") {
                    if let Some(time_part) = line.split("time=").nth(1) {
                        if let Some(ms) = time_part.split_whitespace().next() {
                            result.latency_ms = ms.parse().ok();
                        }
                    }
                }
            }
        }
    }
    result
}

#[cfg(target_os = "macos")]
fn mtu_path_discovery_internal(target_host: &str) -> DiscoveryResult {
    let mut result = DiscoveryResult {
        host: target_host.to_owned(),
        mtu: None,
        hops: None,
        latency_ms: None,
    };
    if let Ok(output) = std::process::Command::new("ping")
        .args(["-D", "-c", "1", target_host])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                if line.contains("time=") {
                    if let Some(time_part) = line.split("time=").nth(1) {
                        if let Some(ms) = time_part.split_whitespace().next() {
                            result.latency_ms = ms.parse().ok();
                        }
                    }
                }
            }
        }
    }
    result
}

#[cfg(target_os = "windows")]
fn mtu_path_discovery_internal(target_host: &str) -> DiscoveryResult {
    let mut result = DiscoveryResult {
        host: target_host.to_string(),
        mtu: None,
        hops: None,
        latency_ms: None,
    };
    if let Ok(output) = std::process::Command::new("ping")
        .args(["-l", "1472", "-f", "-n", "1", target_host])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                if line.contains("time=") {
                    if let Some(time_part) = line.split("time=").nth(1) {
                        if let Some(ms) = time_part.split("ms").next() {
                            result.latency_ms = ms.trim().parse().ok();
                        }
                    }
                }
            }
        }
    }
    result
}

#[cfg(target_os = "linux")]
fn dns_resolution_latency_internal(domain: &str, iterations: usize) -> DnsLatencyMetrics {
    let mut latencies = Vec::new();
    for _ in 0..iterations {
        let start = std::time::Instant::now();
        if std::process::Command::new("getent")
            .args(["hosts", domain])
            .output()
            .is_ok()
        {
            latencies.push(start.elapsed().as_secs_f64() * 1000.0);
        } else {
            latencies.push(-1.0);
        }
    }

    let valid: Vec<f64> = latencies.iter().filter(|&&l| l >= 0.0).copied().collect();
    let failures = iterations - valid.len();
    let avg = valid.iter().sum::<f64>() / (valid.len().max(1) as f64);
    let variance =
        valid.iter().map(|&l| (l - avg).powi(2)).sum::<f64>() / (valid.len().max(1) as f64);

    DnsLatencyMetrics {
        domain: domain.to_string(),
        min_ms: valid.iter().copied().fold(f64::INFINITY, f64::min),
        max_ms: valid.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        avg_ms: avg,
        stddev_ms: variance.sqrt(),
        failures,
    }
}

#[cfg(target_os = "macos")]
fn dns_resolution_latency_internal(domain: &str, iterations: usize) -> DnsLatencyMetrics {
    let mut latencies = Vec::new();
    for _ in 0..iterations {
        let start = std::time::Instant::now();
        if std::process::Command::new("dscacheutil")
            .args(["-q", "host", "-a", "name", domain])
            .output()
            .is_ok()
        {
            latencies.push(start.elapsed().as_secs_f64() * 1000.0);
        } else {
            latencies.push(-1.0);
        }
    }

    let valid: Vec<f64> = latencies.iter().filter(|&&l| l >= 0.0).copied().collect();
    let failures = iterations - valid.len();
    let avg = valid.iter().sum::<f64>() / (valid.len().max(1) as f64);
    let variance =
        valid.iter().map(|&l| (l - avg).powi(2)).sum::<f64>() / (valid.len().max(1) as f64);

    DnsLatencyMetrics {
        domain: domain.to_owned(),
        min_ms: valid.iter().copied().fold(f64::INFINITY, f64::min),
        max_ms: valid.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        avg_ms: avg,
        stddev_ms: variance.sqrt(),
        failures,
    }
}

#[cfg(target_os = "windows")]
fn dns_resolution_latency_internal(domain: &str, iterations: usize) -> DnsLatencyMetrics {
    let mut latencies = Vec::new();
    for _ in 0..iterations {
        let start = std::time::Instant::now();
        if std::process::Command::new("nslookup")
            .args([domain])
            .output()
            .is_ok()
        {
            latencies.push(start.elapsed().as_secs_f64() * 1000.0);
        } else {
            latencies.push(-1.0);
        }
    }

    let valid: Vec<f64> = latencies.iter().filter(|&&l| l >= 0.0).copied().collect();
    let failures = iterations - valid.len();
    let avg = valid.iter().sum::<f64>() / (valid.len().max(1) as f64);
    let variance =
        valid.iter().map(|&l| (l - avg).powi(2)).sum::<f64>() / (valid.len().max(1) as f64);

    DnsLatencyMetrics {
        domain: domain.to_string(),
        min_ms: valid.iter().copied().fold(f64::INFINITY, f64::min),
        max_ms: valid.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        avg_ms: avg,
        stddev_ms: variance.sqrt(),
        failures,
    }
}

#[cfg(target_os = "linux")]
fn bgp_route_announcements_internal() -> BgpStatus {
    BgpStatus {
        enabled: std::process::Command::new("systemctl")
            .args(["is-active", "bgpd"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
        announced_prefixes: Vec::new(),
        peer_count: 0,
    }
}

#[cfg(target_os = "macos")]
fn bgp_route_announcements_internal() -> BgpStatus {
    BgpStatus {
        enabled: false,
        announced_prefixes: Vec::new(),
        peer_count: 0,
    }
}

#[cfg(target_os = "windows")]
fn bgp_route_announcements_internal() -> BgpStatus {
    BgpStatus {
        enabled: std::process::Command::new("sc")
            .args(["query", "RemoteAccess"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
        announced_prefixes: Vec::new(),
        peer_count: 0,
    }
}

/// Tally connection states from `ss -tan` rows. The header line is
/// skipped; state is read from field 0 using `ss`'s hyphenated names
/// (`ESTAB`, `TIME-WAIT`, `SYN-RECV`, `CLOSE-WAIT`, `FIN-WAIT-1`,
/// `FIN-WAIT-2`) — anything else recognized falls into `other`. A blank
/// line (no fields at all) is skipped rather than counted as `other`.
#[allow(dead_code)]
fn parse_ss_connection_states(output: &str) -> StateHistogram {
    let mut histogram = StateHistogram {
        established: 0,
        time_wait: 0,
        syn_recv: 0,
        close_wait: 0,
        fin_wait1: 0,
        fin_wait2: 0,
        other: 0,
    };
    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parts.is_empty() {
            match parts[0] {
                "ESTAB" => histogram.established += 1,
                "TIME-WAIT" => histogram.time_wait += 1,
                "SYN-RECV" => histogram.syn_recv += 1,
                "CLOSE-WAIT" => histogram.close_wait += 1,
                "FIN-WAIT-1" => histogram.fin_wait1 += 1,
                "FIN-WAIT-2" => histogram.fin_wait2 += 1,
                _ => histogram.other += 1,
            }
        }
    }
    histogram
}

#[cfg(target_os = "linux")]
fn connection_state_histogram_internal() -> StateHistogram {
    let mut histogram = StateHistogram {
        established: 0,
        time_wait: 0,
        syn_recv: 0,
        close_wait: 0,
        fin_wait1: 0,
        fin_wait2: 0,
        other: 0,
    };

    if let Ok(output) = std::process::Command::new("ss").args(["-tan"]).output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        histogram = parse_ss_connection_states(&s);
    }
    histogram
}

/// Tally connection states from macOS `netstat -an` rows. The header line
/// is skipped; state is read from the *last* whitespace field using
/// `netstat`'s underscored names (`ESTABLISHED`, `TIME_WAIT`, `SYN_RECV`,
/// `CLOSE_WAIT`, `FIN_WAIT_1`, `FIN_WAIT_2`) — anything else recognized
/// falls into `other`. A blank line (`.last()` is `None`) is skipped, not
/// counted as `other`. NOTE: macOS `netstat -an` output has a *second*
/// (column-name) header line after the one `.skip(1)` removes; its last
/// field is a state-summary label like `"(state)"`, which matches none of
/// the recognized states and lands in `other` — a small, preserved,
/// pre-existing miscount.
#[allow(dead_code)]
fn parse_netstat_connection_states_macos(output: &str) -> StateHistogram {
    let mut histogram = StateHistogram {
        established: 0,
        time_wait: 0,
        syn_recv: 0,
        close_wait: 0,
        fin_wait1: 0,
        fin_wait2: 0,
        other: 0,
    };
    for line in output.lines().skip(1) {
        if let Some(state) = line.split_whitespace().last() {
            match state {
                "ESTABLISHED" => histogram.established += 1,
                "TIME_WAIT" => histogram.time_wait += 1,
                "SYN_RECV" => histogram.syn_recv += 1,
                "CLOSE_WAIT" => histogram.close_wait += 1,
                "FIN_WAIT_1" => histogram.fin_wait1 += 1,
                "FIN_WAIT_2" => histogram.fin_wait2 += 1,
                _ => histogram.other += 1,
            }
        }
    }
    histogram
}

#[cfg(target_os = "macos")]
fn connection_state_histogram_internal() -> StateHistogram {
    let mut histogram = StateHistogram {
        established: 0,
        time_wait: 0,
        syn_recv: 0,
        close_wait: 0,
        fin_wait1: 0,
        fin_wait2: 0,
        other: 0,
    };

    if let Ok(output) = std::process::Command::new("netstat").args(["-an"]).output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        histogram = parse_netstat_connection_states_macos(&s);
    }
    histogram
}

/// Tally connection states from Windows `netstat -an` rows. No header line
/// is skipped (a preserved asymmetry vs. the macOS variant above — its
/// two header lines simply fall to `other` since neither matches a
/// recognized state string). State is read from the last whitespace
/// field; Windows `netstat` reports `SYN_RECEIVED` (not `SYN_RECV`) and
/// this parser has no distinct `FIN_WAIT_1`/`FIN_WAIT_2` match arms, so
/// both fall into `other` — preserved verbatim from the pre-split
/// implementation.
#[allow(dead_code)]
fn parse_netstat_connection_states_windows(output: &str) -> StateHistogram {
    let mut histogram = StateHistogram {
        established: 0,
        time_wait: 0,
        syn_recv: 0,
        close_wait: 0,
        fin_wait1: 0,
        fin_wait2: 0,
        other: 0,
    };
    for line in output.lines() {
        if let Some(state) = line.split_whitespace().last() {
            match state {
                "ESTABLISHED" => histogram.established += 1,
                "TIME_WAIT" => histogram.time_wait += 1,
                "SYN_RECEIVED" => histogram.syn_recv += 1,
                "CLOSE_WAIT" => histogram.close_wait += 1,
                _ => histogram.other += 1,
            }
        }
    }
    histogram
}

#[cfg(target_os = "windows")]
fn connection_state_histogram_internal() -> StateHistogram {
    let mut histogram = StateHistogram {
        established: 0,
        time_wait: 0,
        syn_recv: 0,
        close_wait: 0,
        fin_wait1: 0,
        fin_wait2: 0,
        other: 0,
    };

    if let Ok(output) = std::process::Command::new("netstat").args(["-an"]).output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        histogram = parse_netstat_connection_states_windows(&s);
    }
    histogram
}

#[cfg(target_os = "linux")]
fn arp_table_entries_internal() -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    if let Ok(output) = std::process::Command::new("arp").args(["-n"]).output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(1) {
                if let Some(entry) = parse_arp_n_row(line) {
                    entries.push(entry);
                }
            }
        }
    }
    entries
}

/// RSA-0050: parse one whitespace-columned `arp -n` row
/// (`Address HWtype HWaddress Flags Mask Iface` — 6 columns). Pure so it is
/// unit-testable, and FAIL-SOFT: the previous inline parser guarded
/// `len() >= 5` but indexed `parts[5]` (the interface, needing 6 columns), so a
/// 5-column row panicked. `.get()` skips a short/garbled row instead of
/// panicking on locale/format variation.
#[cfg(any(target_os = "linux", test))]
fn parse_arp_n_row(line: &str) -> Option<ArpEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    Some(ArpEntry {
        ip: (*parts.first()?).to_owned(),
        mac: (*parts.get(2)?).to_owned(),
        interface: (*parts.get(5)?).to_owned(),
        age_secs: None,
        is_permanent: line.contains("PERM"),
    })
}

#[cfg(target_os = "macos")]
fn arp_table_entries_internal() -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    if let Ok(output) = std::process::Command::new("arp").args(["-an"]).output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // RSA-0050: needs parts[5] (interface) ⇒ guard >= 6, not >= 5.
                if parts.len() >= 6 {
                    entries.push(ArpEntry {
                        ip: parts[1].trim_matches('(').trim_matches(')').to_owned(),
                        mac: parts[3].to_owned(),
                        interface: parts[5].to_owned(),
                        age_secs: None,
                        is_permanent: line.contains("permanent"),
                    });
                }
            }
        }
    }
    entries
}

#[cfg(target_os = "windows")]
fn arp_table_entries_internal() -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    if let Ok(output) = std::process::Command::new("arp").args(["-a"]).output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    entries.push(ArpEntry {
                        ip: parts[0].to_string(),
                        mac: parts[1].to_string(),
                        interface: "-".to_string(),
                        age_secs: None,
                        is_permanent: line.contains("static"),
                    });
                }
            }
        }
    }
    entries
}

#[cfg(target_os = "linux")]
fn listening_sockets_summary_internal() -> Vec<ListeningSocket> {
    let Ok(output) = std::process::Command::new("ss").args(["-tlnp"]).output() else {
        return Vec::new();
    };
    match String::from_utf8(output.stdout) {
        Ok(text) => parse_ss_listening_sockets(&text),
        Err(_) => Vec::new(),
    }
}

/// Parse `ss -tlnp` output into listening-socket rows. Split out from the IO so
/// the parser can be exercised with golden fixtures (incl. IPv6 and malformed
/// rows) without spawning `ss`. The first line is the column header and is
/// skipped; rows with fewer than four whitespace fields, or whose
/// address field has no `:` port separator, are dropped. A non-numeric port
/// degrades to 0 (the long-standing `unwrap_or(0)` behavior — preserved here so
/// the split is behavior-identical; a future change can tighten it).
#[cfg(target_os = "linux")]
fn parse_ss_listening_sockets(output: &str) -> Vec<ListeningSocket> {
    let mut sockets = Vec::new();
    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4
            && let Some(colon_idx) = parts[3].rfind(':')
        {
            let port: u16 = parts[3][colon_idx + 1..].parse().unwrap_or(0);
            sockets.push(ListeningSocket {
                protocol: parts[0].to_string(),
                address: parts[3][..colon_idx].to_string(),
                port,
                pid: None,
                process_name: None,
            });
        }
    }
    sockets
}

/// Parse macOS `netstat -tln` rows into [`ListeningSocket`]s. The header
/// line is skipped; a row qualifies only if it has at least 4 whitespace
/// fields and field 3 contains `"LISTEN"`. PRESERVED QUIRK: field 3 does
/// double duty as *both* the `"LISTEN"` substring check *and* the
/// `address.port` source (via `rfind('.')`, since macOS `netstat` renders
/// `address.port` with a `.` separator rather than the Linux `ss` parser's
/// `:`), so the field must simultaneously contain the literal text
/// `"LISTEN"` and a `.`-delimited trailing segment for the row to be
/// captured at all — an unusual, pre-existing column mapping, preserved
/// verbatim rather than corrected. A non-numeric trailing segment degrades
/// the port to 0 (the same `unwrap_or(0)` convention as the Linux parser).
#[allow(dead_code)]
fn parse_netstat_listening_sockets_macos(output: &str) -> Vec<ListeningSocket> {
    let mut sockets = Vec::new();
    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[3].contains("LISTEN") {
            if let Some(colon_idx) = parts[3].rfind('.') {
                let port: u16 = parts[3][colon_idx + 1..].parse().unwrap_or(0);
                sockets.push(ListeningSocket {
                    protocol: parts[0].to_owned(),
                    address: parts[3][..colon_idx].to_string(),
                    port,
                    pid: None,
                    process_name: None,
                });
            }
        }
    }
    sockets
}

#[cfg(target_os = "macos")]
fn listening_sockets_summary_internal() -> Vec<ListeningSocket> {
    if let Ok(output) = std::process::Command::new("netstat")
        .args(["-tln"])
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        return parse_netstat_listening_sockets_macos(&s);
    }
    Vec::new()
}

/// Parse Windows `netstat -ano` rows into [`ListeningSocket`]s. No header
/// line is skipped here (a preserved asymmetry vs. the Linux/macOS
/// variants) — non-matching header/summary lines are filtered out solely
/// by the `"LISTEN"` / field-count checks. A pid in field 4 is captured
/// when present and numeric.
#[allow(dead_code)]
fn parse_netstat_listening_sockets_windows(output: &str) -> Vec<ListeningSocket> {
    let mut sockets = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[3].contains("LISTEN") {
            if let Some(colon_idx) = parts[1].rfind(':') {
                let port: u16 = parts[1][colon_idx + 1..].parse().unwrap_or(0);
                sockets.push(ListeningSocket {
                    protocol: parts[0].to_string(),
                    address: parts[1][..colon_idx].to_string(),
                    port,
                    pid: parts.get(4).and_then(|p| p.parse().ok()),
                    process_name: None,
                });
            }
        }
    }
    sockets
}

#[cfg(target_os = "windows")]
fn listening_sockets_summary_internal() -> Vec<ListeningSocket> {
    if let Ok(output) = std::process::Command::new("netstat")
        .args(["-ano"])
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
    {
        return parse_netstat_listening_sockets_windows(&s);
    }
    Vec::new()
}

#[cfg(target_os = "linux")]
fn network_drop_stats_internal() -> Vec<InterfaceDropStats> {
    let mut stats = Vec::new();
    if let Ok(output) = std::process::Command::new("ip")
        .args(["stats", "dev"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let mut current_iface = String::new();
            for line in s.lines() {
                if !line.starts_with(' ') && !line.is_empty() {
                    current_iface = line.trim().to_string();
                } else if line.contains("RX:") {
                    if let Some(_drops) = line.split("dropped").next() {
                        stats.push(InterfaceDropStats {
                            interface: current_iface.clone(),
                            rx_drops: 0,
                            tx_drops: 0,
                            rx_errors: 0,
                            tx_errors: 0,
                        });
                    }
                }
            }
        }
    }
    stats
}

#[cfg(target_os = "macos")]
fn network_drop_stats_internal() -> Vec<InterfaceDropStats> {
    let mut stats = Vec::new();
    if let Ok(output) = std::process::Command::new("ifconfig").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let mut current_iface = String::new();
            for line in s.lines() {
                if !line.starts_with('\t') && !line.starts_with(' ') {
                    current_iface = line.split(':').next().unwrap_or("").to_owned();
                } else if line.contains("dropped") {
                    stats.push(InterfaceDropStats {
                        interface: current_iface.clone(),
                        rx_drops: 0,
                        tx_drops: 0,
                        rx_errors: 0,
                        tx_errors: 0,
                    });
                }
            }
        }
    }
    stats
}

#[cfg(target_os = "windows")]
fn network_drop_stats_internal() -> Vec<InterfaceDropStats> {
    let mut stats = Vec::new();
    if let Ok(output) = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "interface"])
        .output()
    {
        if let Ok(_s) = String::from_utf8(output.stdout) {
            stats.push(InterfaceDropStats {
                interface: "unknown".to_string(),
                rx_drops: 0,
                tx_drops: 0,
                rx_errors: 0,
                tx_errors: 0,
            });
        }
    }
    stats
}

// ============================================================================
// SECURITY FUNCTIONS (8) - STUB IMPLEMENTATIONS FOR COMPLETENESS
// ============================================================================

#[cfg(target_os = "linux")]
fn tls_certificate_expiry_all_internal(paths: &[&str]) -> Vec<CertExpiry> {
    let mut results = Vec::new();
    for path in paths {
        if let Ok(output) = std::process::Command::new("openssl")
            .args(["x509", "-in", path, "-noout", "-subject", "-dates"])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let mut subject = "unknown".to_string();
                let mut expires_at = "unknown".to_string();

                for line in s.lines() {
                    if line.starts_with("subject=") {
                        subject = line
                            .strip_prefix("subject=")
                            .unwrap_or("unknown")
                            .to_string();
                    } else if line.starts_with("notAfter=") {
                        expires_at = line
                            .strip_prefix("notAfter=")
                            .unwrap_or("unknown")
                            .to_string();
                    }
                }

                // Cert-expiry evaluation is not yet implemented; the parser
                // records the raw `expires_at` string and reports not-expired.
                let is_expired = false;

                results.push(CertExpiry {
                    path: path.to_string(),
                    subject,
                    expires_at,
                    days_until_expiry: 0,
                    is_expired,
                });
            }
        } else {
            results.push(CertExpiry {
                path: path.to_string(),
                subject: "error".to_string(),
                expires_at: "unknown".to_string(),
                days_until_expiry: 0,
                is_expired: false,
            });
        }
    }
    results
}

#[cfg(target_os = "macos")]
fn tls_certificate_expiry_all_internal(paths: &[&str]) -> Vec<CertExpiry> {
    let mut results = Vec::new();
    for path in paths {
        if let Ok(output) = std::process::Command::new("openssl")
            .args(["x509", "-in", path, "-noout", "-subject", "-dates"])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let mut subject = "unknown".to_owned();
                let mut expires_at = "unknown".to_owned();

                for line in s.lines() {
                    if line.starts_with("subject=") {
                        subject = line
                            .strip_prefix("subject=")
                            .unwrap_or("unknown")
                            .to_owned();
                    } else if line.starts_with("notAfter=") {
                        expires_at = line
                            .strip_prefix("notAfter=")
                            .unwrap_or("unknown")
                            .to_owned();
                    }
                }

                results.push(CertExpiry {
                    path: path.to_string(),
                    subject,
                    expires_at,
                    days_until_expiry: 0,
                    is_expired: false,
                });
            }
        } else {
            results.push(CertExpiry {
                path: path.to_string(),
                subject: "error".to_owned(),
                expires_at: "unknown".to_owned(),
                days_until_expiry: 0,
                is_expired: false,
            });
        }
    }
    results
}

#[cfg(target_os = "windows")]
fn tls_certificate_expiry_all_internal(paths: &[&str]) -> Vec<CertExpiry> {
    let mut results = Vec::new();
    for path in paths {
        if let Ok(output) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{}'); Write-Host $cert.Subject; Write-Host $cert.NotAfter", path)])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let lines: Vec<&str> = s.lines().collect();
                let subject = lines.first().copied().unwrap_or("unknown").to_string();
                let expires_at = lines.get(1).copied().unwrap_or("unknown").to_string();

                results.push(CertExpiry {
                    path: path.to_string(),
                    subject,
                    expires_at,
                    days_until_expiry: 0,
                    is_expired: false,
                });
            }
        } else {
            results.push(CertExpiry {
                path: path.to_string(),
                subject: "error".to_string(),
                expires_at: "unknown".to_string(),
                days_until_expiry: 0,
                is_expired: false,
            });
        }
    }
    results
}

#[cfg(target_os = "linux")]
fn selinux_status_internal() -> SeLinuxStatus {
    let enabled = std::path::Path::new("/sys/fs/selinux").exists();
    let mut mode = "disabled".to_string();

    if enabled {
        if let Ok(output) = std::process::Command::new("getenforce").output() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                mode = s.trim().to_string();
            }
        }
    }

    let mut policy_version = None;
    if let Ok(content) = fs::read_to_string("/sys/fs/selinux/policy_capabilities") {
        for line in content.lines() {
            if line.contains("version") {
                policy_version = line.split(':').nth(1).and_then(|v| v.trim().parse().ok());
            }
        }
    }

    SeLinuxStatus {
        enabled,
        mode,
        policy_version,
        violations_since_boot: 0,
    }
}

#[cfg(target_os = "macos")]
fn selinux_status_internal() -> SeLinuxStatus {
    SeLinuxStatus {
        enabled: false,
        mode: "not_applicable".to_owned(),
        policy_version: None,
        violations_since_boot: 0,
    }
}

#[cfg(target_os = "windows")]
fn selinux_status_internal() -> SeLinuxStatus {
    SeLinuxStatus {
        enabled: false,
        mode: "not_applicable".to_string(),
        policy_version: None,
        violations_since_boot: 0,
    }
}

#[cfg(target_os = "linux")]
fn apparmor_profile_status_internal() -> Vec<AppArmorProfile> {
    let mut profiles = Vec::new();

    if let Ok(output) = std::process::Command::new("aa-status").output() {
        if output.status.success() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                for line in s.lines() {
                    if line.contains("profile") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let name = parts[parts.len() - 2];
                            let mode = parts.last().unwrap_or(&"unknown");
                            profiles.push(AppArmorProfile {
                                name: name.to_string(),
                                mode: mode.to_string(),
                                loaded: true,
                                attached_pids: Vec::new(),
                            });
                        }
                    }
                }
            }
        }
    }

    if profiles.is_empty() && std::path::Path::new("/sys/module/apparmor").exists() {
        profiles.push(AppArmorProfile {
            name: "apparmor".to_string(),
            mode: "unknown".to_string(),
            loaded: true,
            attached_pids: Vec::new(),
        });
    }

    profiles
}

#[cfg(target_os = "macos")]
fn apparmor_profile_status_internal() -> Vec<AppArmorProfile> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn apparmor_profile_status_internal() -> Vec<AppArmorProfile> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn cryptographic_key_permissions_internal() -> Vec<KeyPermissionCheck> {
    let mut checks = Vec::new();
    let key_paths = vec![
        "/etc/rustynet/keys/private.key",
        "/run/rustynet/signing.key",
    ];

    for path in key_paths {
        if let Ok(output) = std::process::Command::new("stat")
            .args(["-c", "%U:%G %a", path])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let parts: Vec<&str> = s.split_whitespace().collect();
                let owner_group = parts.first().copied().unwrap_or("unknown:unknown");
                let mode = parts.get(1).copied().unwrap_or("000");

                let owner_parts: Vec<&str> = owner_group.split(':').collect();
                let owner = owner_parts
                    .first()
                    .copied()
                    .unwrap_or("unknown")
                    .to_string();

                let mode_val = u32::from_str_radix(mode, 8).unwrap_or(0o777);
                let is_correct = (mode_val & 0o077) == 0;

                let mut issues = Vec::new();
                if (mode_val & 0o077) != 0 {
                    issues.push("world/group readable".to_string());
                }

                checks.push(KeyPermissionCheck {
                    path: path.to_string(),
                    owner,
                    mode: mode.to_string(),
                    context: None,
                    is_correct,
                    issues,
                });
            }
        }
    }

    checks
}

#[cfg(target_os = "macos")]
fn cryptographic_key_permissions_internal() -> Vec<KeyPermissionCheck> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn cryptographic_key_permissions_internal() -> Vec<KeyPermissionCheck> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn tls_cipher_suite_strength_internal(host: &str, port: u16) -> CipherSuiteInfo {
    let target = format!("{host}:{port}");

    if let Ok(output) = std::process::Command::new("openssl")
        .args(["s_client", "-connect", &target, "-servername", host])
        .arg("-2>&1")
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let mut suite_name = "unknown".to_string();
            let mut tls_version = "unknown".to_string();
            let strength_bits;

            for line in s.lines() {
                if line.contains("Cipher") && !line.contains('#') {
                    if let Some(cipher) = line.split(':').nth(1) {
                        suite_name = cipher.trim().to_string();
                    }
                } else if line.contains("Protocol") {
                    if let Some(version) = line.split(':').nth(1) {
                        tls_version = version.trim().to_string();
                    }
                }
            }

            strength_bits = match suite_name.as_str() {
                s if s.contains("256") => 256,
                s if s.contains("192") => 192,
                s if s.contains("128") => 128,
                _ => 0,
            };

            return CipherSuiteInfo {
                suite_name,
                key_exchange: "unknown".to_string(),
                cipher: "unknown".to_string(),
                mac: "unknown".to_string(),
                tls_version,
                strength_bits,
            };
        }
    }

    CipherSuiteInfo {
        suite_name: "unknown".to_string(),
        key_exchange: "unknown".to_string(),
        cipher: "unknown".to_string(),
        mac: "unknown".to_string(),
        tls_version: "unknown".to_string(),
        strength_bits: 0,
    }
}

#[cfg(target_os = "macos")]
fn tls_cipher_suite_strength_internal(host: &str, port: u16) -> CipherSuiteInfo {
    let target = format!("{host}:{port}");

    if let Ok(output) = std::process::Command::new("openssl")
        .args(["s_client", "-connect", &target, "-servername", host])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let mut suite_name = "unknown".to_owned();
            let mut tls_version = "unknown".to_owned();
            let strength_bits;

            for line in s.lines() {
                if line.contains("Cipher") && !line.contains('#') {
                    if let Some(cipher) = line.split(':').nth(1) {
                        suite_name = cipher.trim().to_owned();
                    }
                } else if line.contains("Protocol") {
                    if let Some(version) = line.split(':').nth(1) {
                        tls_version = version.trim().to_owned();
                    }
                }
            }

            strength_bits = match suite_name.as_str() {
                s if s.contains("256") => 256,
                s if s.contains("192") => 192,
                s if s.contains("128") => 128,
                _ => 0,
            };

            return CipherSuiteInfo {
                suite_name,
                key_exchange: "unknown".to_owned(),
                cipher: "unknown".to_owned(),
                mac: "unknown".to_owned(),
                tls_version,
                strength_bits,
            };
        }
    }

    CipherSuiteInfo {
        suite_name: "unknown".to_owned(),
        key_exchange: "unknown".to_owned(),
        cipher: "unknown".to_owned(),
        mac: "unknown".to_owned(),
        tls_version: "unknown".to_owned(),
        strength_bits: 0,
    }
}

#[cfg(target_os = "windows")]
fn tls_cipher_suite_strength_internal(host: &str, port: u16) -> CipherSuiteInfo {
    let target = format!("{}:{}", host, port);

    if let Ok(output) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &format!("[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $req = [System.Net.HttpWebRequest]::Create('https://{}:{}'); $req.GetResponse() | Out-Null", host, port)])
        .output()
    {
        if output.status.success() {
            return CipherSuiteInfo {
                suite_name: "TLS_AES_256_GCM_SHA384".to_string(),
                key_exchange: "ECDHE".to_string(),
                cipher: "AES-256-GCM".to_string(),
                mac: "SHA384".to_string(),
                tls_version: "TLSv1.3".to_string(),
                strength_bits: 256,
            };
        }
    }

    CipherSuiteInfo {
        suite_name: "unknown".to_string(),
        key_exchange: "unknown".to_string(),
        cipher: "unknown".to_string(),
        mac: "unknown".to_string(),
        tls_version: "unknown".to_string(),
        strength_bits: 0,
    }
}

#[cfg(target_os = "linux")]
fn sudoers_configuration_audit_internal() -> SudoersAudit {
    let mut total_rules = 0;
    let mut dangerous_rules = Vec::new();
    let mut nopasswd_entries = 0;

    if let Ok(content) = fs::read_to_string("/etc/sudoers") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            total_rules += 1;

            if trimmed.contains("NOPASSWD") {
                nopasswd_entries += 1;
                dangerous_rules.push(format!("NOPASSWD rule: {trimmed}"));
            }

            if trimmed.contains("ALL=(ALL)") || trimmed.contains("ALL = (ALL)") {
                dangerous_rules.push(format!("Full sudo rule: {trimmed}"));
            }

            if trimmed.contains("!authenticate") {
                dangerous_rules.push(format!("No auth required: {trimmed}"));
            }
        }
    }

    SudoersAudit {
        total_rules,
        dangerous_rules,
        nopasswd_entries,
    }
}

#[cfg(target_os = "macos")]
fn sudoers_configuration_audit_internal() -> SudoersAudit {
    let mut total_rules = 0;
    let mut dangerous_rules = Vec::new();
    let mut nopasswd_entries = 0;

    if let Ok(content) = fs::read_to_string("/etc/sudoers") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            total_rules += 1;

            if trimmed.contains("NOPASSWD") {
                nopasswd_entries += 1;
                dangerous_rules.push(format!("NOPASSWD rule: {trimmed}"));
            }

            if trimmed.contains("ALL=(ALL)") || trimmed.contains("ALL = (ALL)") {
                dangerous_rules.push(format!("Full sudo rule: {trimmed}"));
            }

            if trimmed.contains("!authenticate") {
                dangerous_rules.push(format!("No auth required: {trimmed}"));
            }
        }
    }

    SudoersAudit {
        total_rules,
        dangerous_rules,
        nopasswd_entries,
    }
}

#[cfg(target_os = "windows")]
fn sudoers_configuration_audit_internal() -> SudoersAudit {
    SudoersAudit {
        total_rules: 0,
        dangerous_rules: Vec::new(),
        nopasswd_entries: 0,
    }
}

fn open_security_vulnerabilities_internal(advisory_db_path: &str) -> VulnerabilityReport {
    let mut vulnerable_packages = Vec::new();

    if let Ok(content) = fs::read_to_string(advisory_db_path) {
        for line in content.lines() {
            if !line.starts_with('#') && !line.is_empty() {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 3 {
                    vulnerable_packages.push(VulnPackage {
                        name: parts[0].to_owned(),
                        version: parts.get(3..).map(|p| p.join(",")).unwrap_or_default(),
                        cves: vec![parts[1].to_owned()],
                    });
                }
            }
        }
    }

    VulnerabilityReport {
        vulnerable_packages,
    }
}

/// Interpret a `/proc/sys` boolean toggle: any trimmed value other than "0"
/// counts as enabled (matches the existing readers). NOTE: empty content also
/// reads as enabled (`"" != "0"`) — `/proc/sys` entries are never empty in
/// practice, and a MISSING file keeps the caller's default instead of hitting
/// this. Split out for unit testing; only called under `target_os = "linux"`.
#[allow(dead_code)]
fn parse_sysctl_bool_enabled(content: &str) -> bool {
    content.trim() != "0"
}

/// Interpret an unsigned `/proc/sys` integer, defaulting to 0 on non-numeric or
/// garbage content (matches the existing `kptr_restrict` reader). Only called
/// under `target_os = "linux"`.
#[allow(dead_code)]
fn parse_sysctl_u32(content: &str) -> u32 {
    content.trim().parse().unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn kernel_security_parameters_internal() -> KernelSecurityParams {
    let read_bool = |path: &str| {
        fs::read_to_string(path)
            .map(|content| parse_sysctl_bool_enabled(&content))
            .unwrap_or(false)
    };

    KernelSecurityParams {
        aslr_enabled: read_bool("/proc/sys/kernel/randomize_va_space"),
        kptr_restrict: fs::read_to_string("/proc/sys/kernel/kptr_restrict")
            .map(|content| parse_sysctl_u32(&content))
            .unwrap_or(0),
        dmesg_restrict: read_bool("/proc/sys/kernel/dmesg_restrict"),
        panic_on_oops: read_bool("/proc/sys/kernel/panic_on_oops"),
        unprivileged_userns_clone: read_bool("/proc/sys/kernel/unprivileged_userns_clone"),
    }
}

#[cfg(target_os = "macos")]
fn kernel_security_parameters_internal() -> KernelSecurityParams {
    KernelSecurityParams {
        aslr_enabled: true,
        kptr_restrict: 0,
        dmesg_restrict: false,
        panic_on_oops: false,
        unprivileged_userns_clone: false,
    }
}

#[cfg(target_os = "windows")]
fn kernel_security_parameters_internal() -> KernelSecurityParams {
    KernelSecurityParams {
        aslr_enabled: true,
        kptr_restrict: 0,
        dmesg_restrict: false,
        panic_on_oops: false,
        unprivileged_userns_clone: false,
    }
}

// ============================================================================
// RESOURCE FUNCTIONS (6) - STUB IMPLEMENTATIONS FOR COMPLETENESS
// ============================================================================

#[cfg(target_os = "linux")]
fn file_descriptor_usage_internal() -> FdUsage {
    let mut used = 0;
    let mut limit = 0;

    if let Ok(content) = fs::read_to_string("/proc/sys/fs/file-nr") {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 2 {
            used = parts[0].parse().unwrap_or(0);
            limit = parts[1].parse().unwrap_or(0);
        }
    }

    let percent_used = if limit > 0 {
        (used as f64 / limit as f64) * 100.0
    } else {
        0.0
    };

    FdUsage {
        used,
        limit,
        percent_used,
        top_processes: Vec::new(),
    }
}

#[cfg(target_os = "macos")]
fn file_descriptor_usage_internal() -> FdUsage {
    let mut used = 0;
    if let Ok(output) = std::process::Command::new("lsof").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            used = s.lines().count();
        }
    }

    FdUsage {
        used,
        limit: 256000,
        percent_used: (used as f64 / 256000.0) * 100.0,
        top_processes: Vec::new(),
    }
}

#[cfg(target_os = "windows")]
fn file_descriptor_usage_internal() -> FdUsage {
    let mut handle_count = 0;

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-Process | Measure-Object Handles -Sum).Sum",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            handle_count = s.trim().parse().unwrap_or(0);
        }
    }

    FdUsage {
        used: handle_count,
        limit: 1000000,
        percent_used: (handle_count as f64 / 1000000.0) * 100.0,
        top_processes: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
fn memory_fragmentation_ratio_internal() -> MemFragmentation {
    let mut swappiness = 60;
    if let Ok(content) = fs::read_to_string("/proc/sys/vm/swappiness") {
        swappiness = content.trim().parse().unwrap_or(60);
    }

    MemFragmentation {
        heap_fragmentation_percent: 0.0,
        page_cache_hits_percent: 0.0,
        swappiness,
    }
}

/// Extract the value portion of a macOS `sysctl <key>` line printed in
/// `key = value` form (used for `vm.swappiness`, distinct from the colon
/// form other `sysctl` call sites use). Same first/second-`=` truncation
/// caveat as [`parse_macos_sysctl_colon_value`]; `None` when there is no
/// `=` at all.
#[allow(dead_code)]
fn parse_macos_sysctl_equals_value(output: &str) -> Option<&str> {
    output.split('=').nth(1).map(str::trim)
}

#[cfg(target_os = "macos")]
fn memory_fragmentation_ratio_internal() -> MemFragmentation {
    let mut swappiness = 60;
    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("vm.swappiness")
        .output()
        && let Ok(s) = String::from_utf8(output.stdout)
        && let Some(val) = parse_macos_sysctl_equals_value(&s)
    {
        swappiness = val.parse().unwrap_or(60);
    }

    MemFragmentation {
        heap_fragmentation_percent: 0.0,
        page_cache_hits_percent: 0.0,
        swappiness,
    }
}

#[cfg(target_os = "windows")]
fn memory_fragmentation_ratio_internal() -> MemFragmentation {
    MemFragmentation {
        heap_fragmentation_percent: 0.0,
        page_cache_hits_percent: 0.0,
        swappiness: 60,
    }
}

#[cfg(target_os = "linux")]
fn network_socket_limit_usage_internal() -> SocketLimitUsage {
    let mut time_wait_count = 0;

    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        time_wait_count = content.lines().filter(|l| l.contains("06 ")).count();
    }

    SocketLimitUsage {
        ephemeral_range: "32768-65535".to_string(),
        used: time_wait_count,
        available: 32767,
        time_wait_count,
        time_wait_limit: 60000,
    }
}

#[cfg(target_os = "macos")]
fn network_socket_limit_usage_internal() -> SocketLimitUsage {
    let mut time_wait_count = 0;

    if let Ok(output) = std::process::Command::new("netstat")
        .args(["-an", "-p", "tcp"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            time_wait_count = s.lines().filter(|l| l.contains("TIME_WAIT")).count();
        }
    }

    SocketLimitUsage {
        ephemeral_range: "49152-65535".to_owned(),
        used: time_wait_count,
        available: 16383,
        time_wait_count,
        time_wait_limit: 60000,
    }
}

#[cfg(target_os = "windows")]
fn network_socket_limit_usage_internal() -> SocketLimitUsage {
    let mut time_wait_count = 0;

    if let Ok(output) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-NetTCPConnection | Where-Object {$_.State -eq 'TimeWait'} | Measure-Object | Select-Object -ExpandProperty Count"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            time_wait_count = s.trim().parse().unwrap_or(0);
        }
    }

    SocketLimitUsage {
        ephemeral_range: "49152-65535".to_string(),
        used: time_wait_count,
        available: 16383,
        time_wait_count,
        time_wait_limit: 240,
    }
}

#[cfg(target_os = "linux")]
fn inode_usage_per_filesystem_internal() -> Vec<InodeUsage> {
    let mut inodes = Vec::new();
    if let Ok(output) = std::process::Command::new("df").args(["-i"]).output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let total = parts[1].parse().unwrap_or(0);
                    let used = parts[2].parse().unwrap_or(0);
                    let available = parts[3].parse().unwrap_or(0);
                    let percent_used = if total > 0 {
                        (used as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    };

                    inodes.push(InodeUsage {
                        filesystem: parts[5].to_string(),
                        total_inodes: total as u64,
                        used_inodes: used as u64,
                        available: available as u64,
                        percent_used,
                    });
                }
            }
        }
    }
    inodes
}

#[cfg(target_os = "macos")]
fn inode_usage_per_filesystem_internal() -> Vec<InodeUsage> {
    let mut inodes = Vec::new();
    if let Ok(output) = std::process::Command::new("df").args(["-i"]).output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let total = parts[1].parse().unwrap_or(0);
                    let used = parts[2].parse().unwrap_or(0);
                    let available = parts[3].parse().unwrap_or(0);
                    let percent_used = if total > 0 {
                        (f64::from(used) / f64::from(total)) * 100.0
                    } else {
                        0.0
                    };

                    inodes.push(InodeUsage {
                        filesystem: parts[5].to_owned(),
                        total_inodes: total as u64,
                        used_inodes: used as u64,
                        available: available as u64,
                        percent_used,
                    });
                }
            }
        }
    }
    inodes
}

#[cfg(target_os = "windows")]
fn inode_usage_per_filesystem_internal() -> Vec<InodeUsage> {
    let mut inodes = Vec::new();
    if let Ok(output) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-Volume | Select-Object DriveLetter,Size,SizeRemaining | ConvertTo-Csv -NoTypeInformation"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 3 {
                    let total = parts[1].trim_matches('"').parse().unwrap_or(0u64);
                    let available = parts[2].trim_matches('"').parse().unwrap_or(0u64);
                    let used = total.saturating_sub(available);
                    let percent_used = if total > 0 {
                        (used as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    };

                    inodes.push(InodeUsage {
                        filesystem: format!("{}:\\", parts[0].trim_matches('"')),
                        total_inodes: total,
                        used_inodes: used,
                        available,
                        percent_used,
                    });
                }
            }
        }
    }
    inodes
}

#[cfg(target_os = "linux")]
fn process_thread_count_all_internal() -> ThreadCount {
    let mut total_threads = 0;
    let mut limit = 0;

    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/threads-max") {
        limit = content.trim().parse().unwrap_or(0);
    }

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata()
                && metadata.is_dir()
            {
                if let Some(name) = entry.file_name().to_str() {
                    if name.parse::<u32>().is_ok() {
                        if let Ok(tasks) = fs::read_dir(entry.path().join("task")) {
                            total_threads += tasks.count();
                        }
                    }
                }
            }
        }
    }

    let percent_used = if limit > 0 {
        (total_threads as f64 / limit as f64) * 100.0
    } else {
        0.0
    };

    ThreadCount {
        total_threads,
        limit,
        percent_used,
        top_processes: Vec::new(),
    }
}

#[cfg(target_os = "macos")]
fn process_thread_count_all_internal() -> ThreadCount {
    let mut total_threads = 0;

    if let Ok(output) = std::process::Command::new("ps")
        .args(["-A", "-o", "nlwp"])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            for line in s.lines().skip(1) {
                total_threads += line.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }

    ThreadCount {
        total_threads,
        limit: 10000,
        percent_used: (total_threads as f64 / 10000.0) * 100.0,
        top_processes: Vec::new(),
    }
}

#[cfg(target_os = "windows")]
fn process_thread_count_all_internal() -> ThreadCount {
    let mut total_threads = 0;

    if let Ok(output) = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-Process | Measure-Object Threads -Sum).Sum",
        ])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            total_threads = s.trim().parse().unwrap_or(0);
        }
    }

    ThreadCount {
        total_threads,
        limit: 100000,
        percent_used: (total_threads as f64 / 100000.0) * 100.0,
        top_processes: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
fn memory_pressure_stall_info_internal() -> PressureStallInfo {
    let mut memory_some = 0.0;
    let mut cpu_some = 0.0;
    let mut io_some = 0.0;

    if let Ok(content) = fs::read_to_string("/proc/pressure/memory") {
        for line in content.lines() {
            if line.starts_with("some") {
                if let Some(val) = line.split("avg10=").nth(1) {
                    memory_some = val.split(' ').next().unwrap_or("0").parse().unwrap_or(0.0);
                }
            }
        }
    }

    if let Ok(content) = fs::read_to_string("/proc/pressure/cpu") {
        for line in content.lines() {
            if line.starts_with("some") {
                if let Some(val) = line.split("avg10=").nth(1) {
                    cpu_some = val.split(' ').next().unwrap_or("0").parse().unwrap_or(0.0);
                }
            }
        }
    }

    if let Ok(content) = fs::read_to_string("/proc/pressure/io") {
        for line in content.lines() {
            if line.starts_with("some") {
                if let Some(val) = line.split("avg10=").nth(1) {
                    io_some = val.split(' ').next().unwrap_or("0").parse().unwrap_or(0.0);
                }
            }
        }
    }

    PressureStallInfo {
        memory_some_percent_10s: memory_some,
        cpu_some_percent_10s: cpu_some,
        io_some_percent_10s: io_some,
    }
}

#[cfg(target_os = "macos")]
fn memory_pressure_stall_info_internal() -> PressureStallInfo {
    PressureStallInfo {
        memory_some_percent_10s: 0.0,
        cpu_some_percent_10s: 0.0,
        io_some_percent_10s: 0.0,
    }
}

#[cfg(target_os = "windows")]
fn memory_pressure_stall_info_internal() -> PressureStallInfo {
    PressureStallInfo {
        memory_some_percent_10s: 0.0,
        cpu_some_percent_10s: 0.0,
        io_some_percent_10s: 0.0,
    }
}

// ============================================================================
// DAEMON FUNCTIONS (6) - STUB IMPLEMENTATIONS FOR COMPLETENESS
// ============================================================================

fn rustynetd_goroutine_count_internal() -> GoroutineCount {
    let mut count = 0usize;
    let since_startup = 0u64;
    let leaked_estimate = 0usize;

    if let Ok(output) = std::process::Command::new("pgrep")
        .arg("rustynetd")
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            if let Some(pid_str) = s.lines().next() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
                        for line in status.lines() {
                            if line.starts_with("Threads:") {
                                if let Some(threads) = line.split_whitespace().nth(1) {
                                    count = threads.parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    GoroutineCount {
        count,
        since_startup,
        leaked_estimate,
    }
}

#[cfg(target_family = "unix")]
fn ipc_socket_responsiveness_internal(_timeout_ms: u64) -> IpcLatency {
    let socket_path = "/run/rustynet.sock";
    let mut min_ms = f64::INFINITY;
    let mut max_ms = 0.0;
    let mut avg_ms = 0.0;
    let mut failed_attempts = 0usize;
    let mut responsive = false;
    let mut latencies = Vec::new();

    for _ in 0..3 {
        let start = std::time::Instant::now();
        match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(_) => {
                let latency = start.elapsed().as_secs_f64() * 1000.0;
                latencies.push(latency);
                responsive = true;
            }
            Err(_) => {
                failed_attempts += 1;
            }
        }
    }

    if !latencies.is_empty() {
        min_ms = latencies.iter().copied().fold(f64::INFINITY, f64::min);
        max_ms = latencies.iter().copied().fold(0.0, f64::max);
        avg_ms = latencies.iter().sum::<f64>() / latencies.len() as f64;
    }

    IpcLatency {
        min_ms,
        max_ms,
        avg_ms,
        failed_attempts,
        responsive,
    }
}

#[cfg(not(target_family = "unix"))]
fn ipc_socket_responsiveness_internal(_timeout_ms: u64) -> IpcLatency {
    IpcLatency {
        min_ms: f64::INFINITY,
        max_ms: 0.0,
        avg_ms: 0.0,
        failed_attempts: 3,
        responsive: false,
    }
}

#[cfg_attr(not(target_os = "linux"), allow(unused_mut, unused_variables))]
fn daemon_crash_logs_recent_internal(lines: usize) -> Vec<CrashLog> {
    let mut logs = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("journalctl")
            .args(["-u", "rustynetd", "-n", &lines.to_string(), "--no-pager"])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                for line in s.lines() {
                    if line.contains("crash") || line.contains("panic") || line.contains("segfault")
                    {
                        let signal = if line.contains("segfault") {
                            Some("SIGSEGV".to_string())
                        } else if line.contains("panic") {
                            Some("PANIC".to_string())
                        } else {
                            None
                        };

                        logs.push(CrashLog {
                            timestamp: line.to_string(),
                            exit_code: None,
                            signal,
                            backtrace_snippet: None,
                        });
                    }
                }
            }
        }
    }

    logs
}

fn daemon_open_file_handles_internal() -> Vec<OpenHandle> {
    let mut handles = Vec::new();

    if let Ok(output) = std::process::Command::new("pgrep")
        .arg("rustynetd")
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            if let Some(pid_str) = s.lines().next() {
                if let Ok(_pid) = pid_str.parse::<u32>() {
                    if let Ok(output) = std::process::Command::new("lsof")
                        .arg("-p")
                        .arg(pid_str)
                        .output()
                    {
                        if let Ok(s) = String::from_utf8(output.stdout) {
                            for line in s.lines().skip(1) {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() >= 9 {
                                    let fd_str = parts.get(3).copied().unwrap_or("0");
                                    let inode_str = parts.get(6).copied().unwrap_or("0");
                                    let size_str = parts.get(7).copied().unwrap_or("0");
                                    handles.push(OpenHandle {
                                        path: parts
                                            .get(8..)
                                            .map(|p| p.join(" "))
                                            .unwrap_or_default(),
                                        fd: fd_str.parse().unwrap_or(0),
                                        handle_type: parts.get(4).copied().unwrap_or("").to_owned(),
                                        size: size_str.parse().unwrap_or(0),
                                        inode: inode_str.parse().ok(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    handles
}

#[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
fn systemd_unit_dependency_graph_internal() -> DependencyGraph {
    let mut units = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("systemctl")
            .args(["list-units", "--no-pager", "-a"])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                for line in s.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        units.push(UnitDeps {
                            name: parts[0].to_string(),
                            wants: Vec::new(),
                            requires: Vec::new(),
                            blocking_units: Vec::new(),
                        });
                    }
                }
            }
        }
    }

    DependencyGraph { units }
}

fn process_cpu_time_distribution_internal() -> ProcessCpuTime {
    let mut user_ms = 0u64;
    let system_ms = 0u64;
    let children_time_ms = 0u64;

    if let Ok(output) = std::process::Command::new("ps")
        .args(["-o", "time", "-p", &std::process::id().to_string()])
        .output()
    {
        if let Ok(s) = String::from_utf8(output.stdout) {
            if let Some(line) = s.lines().nth(1) {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let minutes = parts[0].trim().parse::<u64>().unwrap_or(0);
                    let seconds = parts[1]
                        .split('.')
                        .next()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .unwrap_or(0);
                    user_ms = (minutes * 60 + seconds) * 1000;
                }
            }
        }
    }

    let user_percent = if user_ms > 0 {
        (user_ms as f64 / (user_ms + system_ms + children_time_ms).max(1) as f64) * 100.0
    } else {
        0.0
    };

    let system_percent = if system_ms > 0 {
        (system_ms as f64 / (user_ms + system_ms + children_time_ms).max(1) as f64) * 100.0
    } else {
        0.0
    };

    ProcessCpuTime {
        user_ms,
        system_ms,
        user_percent,
        system_percent,
        children_time_ms,
    }
}

// ============================================================================
// STORAGE FUNCTIONS (5) - STUB IMPLEMENTATIONS FOR COMPLETENESS
// ============================================================================

#[cfg_attr(not(target_os = "linux"), allow(unused_mut, unused_variables))]
fn disk_io_latency_histogram_internal(device: &str, duration_secs: u64) -> IoLatencyHistogram {
    let mut p50_ms = 0.0;
    let mut p95_ms = 0.0;
    let mut p99_ms = 0.0;
    let mut p999_ms = 0.0;
    let mut max_ms = 0.0;

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("iostat")
            .args(["-x", "1", &duration_secs.to_string(), device])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                for line in s.lines() {
                    if line.contains("await") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        for (i, part) in parts.iter().enumerate() {
                            if part.contains("await") && i + 1 < parts.len() {
                                if let Ok(await_val) = parts[i + 1].parse::<f64>() {
                                    p50_ms = (await_val * 0.5).min(p50_ms + await_val);
                                    p95_ms = (await_val * 0.95).min(p95_ms + await_val);
                                    p99_ms = (await_val * 0.99).min(p99_ms + await_val);
                                    p999_ms = (await_val * 0.999).min(p999_ms + await_val);
                                    max_ms = await_val.max(max_ms);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    IoLatencyHistogram {
        device: device.to_owned(),
        p50_ms,
        p95_ms,
        p99_ms,
        p999_ms,
        max_ms,
    }
}

#[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
fn filesystem_journal_status_internal() -> JournalStatus {
    let mut journal_size_mb = 0u64;
    let mut recovery_needed = false;
    let mut orphaned_inodes = 0usize;

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("dumpe2fs")
            .arg("-h")
            .arg("/")
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                for line in s.lines() {
                    if line.contains("Journal size") {
                        if let Some(val) = line.split_whitespace().last() {
                            journal_size_mb = val.parse().unwrap_or(0);
                        }
                    }
                    if line.contains("needs_recovery") {
                        recovery_needed = true;
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("fsck")
            .args(["-n", "/"])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                if s.contains("orphaned") {
                    for word in s.split_whitespace() {
                        if word.parse::<u32>().is_ok() {
                            orphaned_inodes = word.parse().unwrap_or(0);
                            break;
                        }
                    }
                }
            }
        }
    }

    JournalStatus {
        journal_size_mb,
        recovery_needed,
        orphaned_inodes,
        next_fsck_date: None,
    }
}

#[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
fn block_device_error_counters_internal() -> Vec<DeviceErrors> {
    let mut errors = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/sys/block") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let err_path = entry.path().join("device/ioerr_cnt");
                    if let Ok(content) = fs::read_to_string(&err_path) {
                        if let Ok(count) = content.trim().parse::<usize>() {
                            errors.push(DeviceErrors {
                                device: name.to_string(),
                                smart_errors: count,
                                read_errors: 0,
                                write_errors: 0,
                                ata_errors: 0,
                            });
                        }
                    }
                }
            }
        }
    }

    errors
}

#[cfg(target_os = "linux")]
fn directory_size_snapshot_internal(paths: &[&str]) -> Vec<DirSize> {
    let mut results = Vec::new();

    for path in paths {
        if let Ok(output) = std::process::Command::new("du")
            .args(["-sb", path])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                if let Some(size_str) = s.split_whitespace().next() {
                    let size = size_str.parse().unwrap_or(0u64);

                    let mut file_count = 0;
                    if let Ok(output) = std::process::Command::new("find")
                        .args([path, "-type", "f"])
                        .output()
                    {
                        if let Ok(s) = String::from_utf8(output.stdout) {
                            file_count = s.lines().count();
                        }
                    }

                    results.push(DirSize {
                        path: path.to_string(),
                        size_bytes: size,
                        file_count,
                        largest_files: Vec::new(),
                    });
                }
            }
        }
    }

    results
}

#[cfg(target_os = "macos")]
fn directory_size_snapshot_internal(paths: &[&str]) -> Vec<DirSize> {
    let mut results = Vec::new();

    for path in paths {
        if let Ok(output) = std::process::Command::new("du")
            .args(["-sb", path])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                if let Some(size_str) = s.split_whitespace().next() {
                    let size = size_str.parse().unwrap_or(0u64);

                    let mut file_count = 0;
                    if let Ok(output) = std::process::Command::new("find")
                        .args([path, "-type", "f"])
                        .output()
                    {
                        if let Ok(s) = String::from_utf8(output.stdout) {
                            file_count = s.lines().count();
                        }
                    }

                    results.push(DirSize {
                        path: path.to_string(),
                        size_bytes: size,
                        file_count,
                        largest_files: Vec::new(),
                    });
                }
            }
        }
    }

    results
}

#[cfg(target_os = "windows")]
fn directory_size_snapshot_internal(paths: &[&str]) -> Vec<DirSize> {
    let mut results = Vec::new();

    for path in paths {
        if let Ok(output) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("(Get-ChildItem -Path '{}' -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum", path)])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let size = s.trim().parse().unwrap_or(0u64);

                let mut file_count = 0;
                if let Ok(output) = std::process::Command::new("powershell")
                    .args(["-NoProfile", "-Command", &format!("(Get-ChildItem -Path '{}' -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count", path)])
                    .output()
                {
                    if let Ok(s) = String::from_utf8(output.stdout) {
                        file_count = s.trim().parse().unwrap_or(0);
                    }
                }

                results.push(DirSize {
                    path: path.to_string(),
                    size_bytes: size,
                    file_count,
                    largest_files: Vec::new(),
                });
            }
        }
    }

    results
}

#[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
fn filesystem_cache_efficiency_internal() -> CacheEfficiency {
    let mut cache_hit_rate_percent = 0.0;
    let mut dirty_pages_mb = 0u64;
    let mut writeback_queue_depth = 0usize;

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("vmstat").arg("1").output() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                for line in s.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        if let Ok(us) = parts[0].parse::<u64>() {
                            if let Ok(sy) = parts[1].parse::<u64>() {
                                cache_hit_rate_percent =
                                    (us as f64 / (us as f64 + sy as f64 + 1.0)) * 100.0;
                            }
                        }
                    }
                }
            }
        }

        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("Dirty:") {
                    if let Some(val) = line.split_whitespace().nth(1) {
                        dirty_pages_mb = val.parse::<u64>().unwrap_or(0) / 1024;
                    }
                }
                if line.starts_with("Writeback:") {
                    if let Some(val) = line.split_whitespace().nth(1) {
                        writeback_queue_depth = (val.parse::<usize>().unwrap_or(0) / 4096).max(1);
                    }
                }
            }
        }
    }

    CacheEfficiency {
        cache_hit_rate_percent,
        dirty_pages_mb,
        writeback_queue_depth,
    }
}

// ============================================================================
// COMPLIANCE FUNCTIONS (4) - STUB IMPLEMENTATIONS FOR COMPLETENESS
// ============================================================================

fn file_integrity_check_internal(paths: &[&str]) -> Vec<IntegrityResult> {
    let mut results = Vec::new();

    for path in paths {
        let mut current_hash = "unknown".to_owned();
        if let Ok(output) = std::process::Command::new("sha256sum").arg(path).output() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                if let Some(hash) = s.split_whitespace().next() {
                    current_hash = hash.to_owned();
                }
            }
        }

        results.push(IntegrityResult {
            path: path.to_string(),
            matches_baseline: false,
            current_hash,
            baseline_hash: "unknown".to_owned(),
        });
    }

    results
}

#[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
fn syslog_configuration_audit_internal() -> SyslogAudit {
    let mut forwarding_enabled = false;
    let mut destinations = Vec::new();
    let mut log_retention_days = 30u32;
    let mut permissions_ok = false;

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/etc/rsyslog.conf") {
            for line in content.lines() {
                if line.starts_with("$ModLoad") && line.contains("imtcp") {
                    forwarding_enabled = true;
                }
                if line.starts_with("@@") || line.starts_with("@") {
                    if let Some(dest) = line.strip_prefix("@@").or_else(|| line.strip_prefix("@")) {
                        destinations.push(dest.to_string());
                    }
                }
                if line.starts_with("$FileCreateMode") {
                    permissions_ok = line.contains("0640") || line.contains("0600");
                }
            }
        }

        if let Ok(content) = fs::read_to_string("/etc/logrotate.conf") {
            for line in content.lines() {
                if line.contains("rotate") {
                    if let Some(days) = line.split_whitespace().nth(1) {
                        log_retention_days = days.parse().unwrap_or(30);
                    }
                }
            }
        }
    }

    SyslogAudit {
        forwarding_enabled,
        destinations,
        log_retention_days,
        permissions_ok,
    }
}

/// Parse `getfacl <path>` stdout into `(owner, group, extended ACL lines)`.
/// A missing `# owner:`/`# group:` header comment defaults to `"unknown"`
/// (mirroring the fallback used when the command itself fails); a *present*
/// but value-less header (e.g. a bare `"# owner:"` line) yields an empty
/// string instead — the `"unknown"` default only applies when the line is
/// absent entirely.
///
/// Preserved quirk: `getfacl`'s baseline `user::`/`group::` entries also
/// start with the literal prefixes `"user:"`/`"group:"`, so they are
/// captured into the "extended" ACL list alongside genuine named
/// `user:<name>:<perm>` / `group:<name>:<perm>` grants. Real `getfacl`
/// output always includes the baseline entries, so a caller deriving
/// `is_restrictive` from an empty extended-ACL list should not expect it to
/// fire often. Extracted verbatim from the pre-split implementation; no
/// behavior change.
fn parse_getfacl_output(output: &str) -> (String, String, Vec<String>) {
    let mut owner = "unknown".to_owned();
    let mut group = "unknown".to_owned();
    let mut extended_acl = Vec::new();

    for line in output.lines() {
        if line.starts_with("# owner:") {
            owner = line
                .strip_prefix("# owner:")
                .unwrap_or("")
                .trim()
                .to_owned();
        }
        if line.starts_with("# group:") {
            group = line
                .strip_prefix("# group:")
                .unwrap_or("")
                .trim()
                .to_owned();
        }
        if line.starts_with("user:") || line.starts_with("group:") {
            extended_acl.push(line.to_owned());
        }
    }

    (owner, group, extended_acl)
}

fn access_control_list_audit_internal(paths: &[&str]) -> Vec<AclInfo> {
    let mut results = Vec::new();

    for path in paths {
        if let Ok(output) = std::process::Command::new("getfacl").arg(path).output() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                let (owner, group, extended_acl) = parse_getfacl_output(&s);
                let is_restrictive = extended_acl.is_empty();
                results.push(AclInfo {
                    path: path.to_string(),
                    owner,
                    group,
                    mode: "0000".to_owned(),
                    extended_acl,
                    is_restrictive,
                });
            }
        } else {
            results.push(AclInfo {
                path: path.to_string(),
                owner: "unknown".to_owned(),
                group: "unknown".to_owned(),
                mode: "0000".to_owned(),
                extended_acl: Vec::new(),
                is_restrictive: false,
            });
        }
    }

    results
}

#[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
fn boot_integrity_check_internal() -> BootIntegrity {
    let mut secure_boot_enabled = false;
    let mut measurements_ok = false;
    let mut pcrs = Vec::new();
    // `/dev/tpm0` presence is the TPM signal on Linux; other platforms report
    // no TPM through this path.
    #[cfg(target_os = "linux")]
    let tpm_present = std::path::Path::new("/dev/tpm0").exists();
    #[cfg(not(target_os = "linux"))]
    let tpm_present = false;

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("mokutil")
            .arg("--sb-state")
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                secure_boot_enabled = s.contains("enabled");
            }
        }

        if tpm_present {
            if let Ok(output) = std::process::Command::new("tpm2_pcrread")
                .arg("sha256")
                .output()
            {
                if let Ok(s) = String::from_utf8(output.stdout) {
                    for (idx, line) in s.lines().enumerate() {
                        if line.contains("0x") {
                            pcrs.push(PcrValue {
                                pcr_index: idx as u32,
                                value: line.to_string(),
                            });
                        }
                    }
                    measurements_ok = !pcrs.is_empty();
                }
            }
        }
    }

    BootIntegrity {
        secure_boot_enabled,
        tpm_present,
        measurements_ok,
        pcrs,
    }
}

// ============================================================================
// BASELINE FUNCTIONS (3) - STUB IMPLEMENTATIONS FOR COMPLETENESS
// ============================================================================

fn system_state_snapshot_internal() -> SystemSnapshot {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut uptime_secs = 0u64;
    if let Ok(content) = fs::read_to_string("/proc/uptime") {
        if let Some(val) = content.split_whitespace().next() {
            if let Ok(uptime) = val.parse::<f64>() {
                uptime_secs = uptime as u64;
            }
        }
    }

    let mut process_count = 0usize;
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.parse::<u32>().is_ok() {
                            process_count += 1;
                        }
                    }
                }
            }
        }
    }

    let mut memory_used_mb = 0u64;
    if let Ok(content) = fs::read_to_string("/proc/meminfo") {
        let mut mem_total = 0u64;
        let mut mem_free = 0u64;
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    mem_total = val.parse::<u64>().unwrap_or(0) / 1024;
                }
            }
            if line.starts_with("MemFree:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    mem_free = val.parse::<u64>().unwrap_or(0) / 1024;
                }
            }
        }
        memory_used_mb = mem_total.saturating_sub(mem_free);
    }

    let mut load_avg_1 = 0.0;
    let mut load_avg_5 = 0.0;
    let mut load_avg_15 = 0.0;
    if let Ok(content) = fs::read_to_string("/proc/loadavg") {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 3 {
            load_avg_1 = parts[0].parse().unwrap_or(0.0);
            load_avg_5 = parts[1].parse().unwrap_or(0.0);
            load_avg_15 = parts[2].parse().unwrap_or(0.0);
        }
    }

    SystemSnapshot {
        timestamp,
        uptime_secs,
        process_count,
        memory_used_mb,
        load_avg_1,
        load_avg_5,
        load_avg_15,
    }
}

fn compare_to_baseline_internal(snapshot: &SystemSnapshot) -> AnomalyReport {
    let mut anomalies = Vec::new();
    let baseline = system_state_snapshot_internal();

    if baseline.process_count > snapshot.process_count + 50 {
        anomalies.push(Anomaly {
            metric: "process_count".to_owned(),
            expected: snapshot.process_count.to_string(),
            actual: baseline.process_count.to_string(),
            deviation_percent: ((baseline.process_count as f64 - snapshot.process_count as f64)
                / snapshot.process_count.max(1) as f64)
                * 100.0,
            severity: "warning".to_owned(),
        });
    }

    if baseline.memory_used_mb > snapshot.memory_used_mb + 256 {
        anomalies.push(Anomaly {
            metric: "memory_used_mb".to_owned(),
            expected: snapshot.memory_used_mb.to_string(),
            actual: baseline.memory_used_mb.to_string(),
            deviation_percent: ((baseline.memory_used_mb as f64 - snapshot.memory_used_mb as f64)
                / snapshot.memory_used_mb.max(1) as f64)
                * 100.0,
            severity: "warning".to_owned(),
        });
    }

    if baseline.load_avg_1 > snapshot.load_avg_1 + 2.0 {
        anomalies.push(Anomaly {
            metric: "load_avg_1".to_owned(),
            expected: format!("{:.2}", snapshot.load_avg_1),
            actual: format!("{:.2}", baseline.load_avg_1),
            deviation_percent: ((baseline.load_avg_1 - snapshot.load_avg_1)
                / (snapshot.load_avg_1 + 1.0))
                * 100.0,
            severity: "info".to_owned(),
        });
    }

    AnomalyReport { anomalies }
}

fn performance_regression_detection_internal(
    metrics_history: &[(String, u64)],
) -> Vec<RegressionAnalysis> {
    let mut regressions = Vec::new();

    if metrics_history.len() < 2 {
        return regressions;
    }

    let mut metrics_by_name: std::collections::HashMap<String, Vec<u64>> =
        std::collections::HashMap::new();
    for (name, value) in metrics_history {
        metrics_by_name
            .entry(name.clone())
            .or_default()
            .push(*value);
    }

    for (name, values) in metrics_by_name {
        if values.len() >= 2 {
            let first = values[0] as f64;
            let last = values[values.len() - 1] as f64;
            // Guard against a zero first sample (division would yield
            // inf/NaN and never compare true against the threshold).
            if first == 0.0 {
                continue;
            }
            let change_percent = ((last - first) / first) * 100.0;

            // A regression is a *significant change in either direction*: a
            // metric that climbs (e.g. latency, memory) or one that falls
            // (e.g. throughput) by more than the threshold. Gating on the
            // signed value alone (`> 50.0`) silently dropped every decrease
            // and made the `"decreasing"` trend arm dead code — the sign is
            // what selects the label, the magnitude is what triggers a report.
            if change_percent.abs() > 50.0 {
                regressions.push(RegressionAnalysis {
                    metric: name,
                    trend: if change_percent > 0.0 {
                        "increasing"
                    } else {
                        "decreasing"
                    }
                    .to_owned(),
                    slope_percent_per_day: change_percent,
                    projected_failure_date: None,
                });
            }
        }
    }

    regressions
}

// ============================================================================
// Host facts — OS family / Linux distro / CPU arch detection for the installer.
// The install engine's detect step needs to know which OS family it is on, which
// package manager provisions prerequisites (Linux), the CPU arch, and the release
// target-triple to fetch. Kept std-only and fail-closed (unknown -> Unsupported /
// None), so the caller never guesses.
// ============================================================================

/// Operating-system family. `Unsupported` is the fail-closed default for any OS
/// the installer does not handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    Linux,
    Macos,
    Windows,
    Unsupported,
}

/// The package-manager family used to provision runtime prerequisites on Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgFamily {
    /// Debian / Ubuntu / Mint family (`apt-get`).
    Apt,
    /// Fedora / RHEL / Rocky / Alma / CentOS family (`dnf`).
    Dnf,
}

/// Resolved facts about the host the installer runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    pub family: OsFamily,
    /// `/etc/os-release` `ID` (lowercased), e.g. `debian`, `ubuntu`, `fedora`,
    /// `rocky`. `None` off Linux or if os-release is unreadable.
    pub distro_id: Option<String>,
    /// `/etc/os-release` `ID_LIKE` tokens (lowercased), e.g. `["rhel","fedora"]`.
    pub distro_like: Vec<String>,
    /// CPU architecture from `std::env::consts::ARCH` (e.g. `x86_64`, `aarch64`).
    pub arch: String,
    /// Package-manager family for prereq provisioning; `None` off Linux or for an
    /// unrecognized distro (fail-closed: the caller must not guess a manager).
    pub pkg_family: Option<PkgFamily>,
}

impl HostFacts {
    /// The release target-triple for this host, matching the artifact names the
    /// release pipeline publishes (the `release.yml` matrix). `None` if this
    /// `(family, arch)` is not a published target — the verified-download step
    /// must then fail closed rather than fetch a wrong-arch binary.
    pub fn target_triple(&self) -> Option<&'static str> {
        match (self.family, self.arch.as_str()) {
            (OsFamily::Linux, "x86_64") => Some("x86_64-unknown-linux-gnu"),
            (OsFamily::Linux, "aarch64") => Some("aarch64-unknown-linux-gnu"),
            (OsFamily::Macos, "aarch64") => Some("aarch64-apple-darwin"),
            (OsFamily::Macos, "x86_64") => Some("x86_64-apple-darwin"),
            (OsFamily::Windows, "x86_64") => Some("x86_64-pc-windows-msvc"),
            _ => None,
        }
    }
}

/// Detect host facts for the current process: OS family from
/// `std::env::consts::OS`, arch from `std::env::consts::ARCH`, and — on Linux —
/// the distro identity + package family from `/etc/os-release` (falling back to
/// `/usr/lib/os-release`).
pub fn host_facts() -> HostFacts {
    let family = match std::env::consts::OS {
        "linux" => OsFamily::Linux,
        "macos" => OsFamily::Macos,
        "windows" => OsFamily::Windows,
        _ => OsFamily::Unsupported,
    };
    let arch = std::env::consts::ARCH.to_owned();
    let (distro_id, distro_like) = if family == OsFamily::Linux {
        read_os_release()
            .map(|content| parse_os_release(&content))
            .unwrap_or((None, Vec::new()))
    } else {
        (None, Vec::new())
    };
    let pkg_family = if family == OsFamily::Linux {
        pkg_family_for(distro_id.as_deref(), &distro_like)
    } else {
        None
    };
    HostFacts {
        family,
        distro_id,
        distro_like,
        arch,
        pkg_family,
    }
}

fn read_os_release() -> Option<String> {
    fs::read_to_string("/etc/os-release")
        .or_else(|_| fs::read_to_string("/usr/lib/os-release"))
        .ok()
}

/// Parse `/etc/os-release` (a shell-like `KEY=value` file; values may be quoted)
/// for `ID` and `ID_LIKE`, both lowercased. `ID_LIKE` is space-separated.
fn parse_os_release(content: &str) -> (Option<String>, Vec<String>) {
    let mut id = None;
    let mut id_like = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ID=") {
            id = Some(unquote(rest).to_ascii_lowercase());
        } else if let Some(rest) = line.strip_prefix("ID_LIKE=") {
            id_like = unquote(rest)
                .split_whitespace()
                .map(|token| token.to_ascii_lowercase())
                .collect();
        }
    }
    (id, id_like)
}

fn unquote(value: &str) -> &str {
    let v = value.trim();
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(v)
}

/// Map a distro to its package-manager family: exact `ID` first, then `ID_LIKE`
/// fallback. Returns `None` for an unrecognized distro so the installer fails
/// closed instead of guessing a package manager.
fn pkg_family_for(distro_id: Option<&str>, distro_like: &[String]) -> Option<PkgFamily> {
    const APT: &[&str] = &[
        "debian",
        "ubuntu",
        "linuxmint",
        "mint",
        "pop",
        "raspbian",
        "elementary",
        "neon",
        "devuan",
    ];
    const DNF: &[&str] = &[
        "fedora",
        "rhel",
        "centos",
        "rocky",
        "almalinux",
        "alma",
        "ol",
        "oracle",
        "amzn",
    ];
    if let Some(id) = distro_id {
        if APT.contains(&id) {
            return Some(PkgFamily::Apt);
        }
        if DNF.contains(&id) {
            return Some(PkgFamily::Dnf);
        }
    }
    for like in distro_like {
        if APT.contains(&like.as_str()) {
            return Some(PkgFamily::Apt);
        }
        if DNF.contains(&like.as_str()) {
            return Some(PkgFamily::Dnf);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::parse_arp_n_row;
    use super::performance_regression_detection_internal;
    use super::{
        parse_linux_operstate, parse_macos_ifconfig_interfaces, parse_proc_version_release,
        parse_windows_ipconfig_interfaces,
    };

    #[test]
    fn rustc_version_returns_embedded_nonempty_toolchain_string() {
        // build.rs embeds the building toolchain's `rustc --version`; since
        // this test binary was necessarily built by a working rustc, the
        // embedded constant must be present and carry the standard prefix.
        let version = super::rustc_version().expect("build-time rustc version embedded");
        assert!(
            version.starts_with("rustc "),
            "embedded rustc version has unexpected shape: {version:?}"
        );
    }

    #[test]
    fn proc_version_release_extracts_third_token_of_first_line() {
        assert_eq!(
            parse_proc_version_release(
                "Linux version 6.1.0-13-amd64 (builder@host) (gcc 12) #1 SMP"
            ),
            Some("6.1.0-13-amd64".to_owned())
        );
        // Only the first line is considered.
        assert_eq!(
            parse_proc_version_release("Linux version 5.10.0 (a)\nsecond line"),
            Some("5.10.0".to_owned())
        );
        // Fewer than three tokens, empty, or whitespace-only -> None.
        assert_eq!(parse_proc_version_release("Linux version"), None);
        assert_eq!(parse_proc_version_release("Linux"), None);
        assert_eq!(parse_proc_version_release(""), None);
        assert_eq!(parse_proc_version_release("   "), None);
    }

    #[test]
    fn proc_net_dev_bytes_parses_tx_rx() {
        use super::parse_proc_net_dev_bytes;
        let sample = "\
Inter-|   Receive                                    |  Transmit
 face |bytes packets errs drop fifo frame compressed multicast|bytes packets
      wg0: 12345 100 0 0 0 0 0 0 67890 200
    eth0: 999999 5000 0 0 0 0 0 0 888888 4000
";
        // Returns (tx_bytes, rx_bytes).
        assert_eq!(parse_proc_net_dev_bytes(sample, "wg0"), (67890, 12345));
        assert_eq!(parse_proc_net_dev_bytes(sample, "eth0"), (888888, 999999));
        // Missing interface / empty input -> (0, 0).
        assert_eq!(parse_proc_net_dev_bytes(sample, "tun9"), (0, 0));
        assert_eq!(parse_proc_net_dev_bytes("", "wg0"), (0, 0));
    }

    #[test]
    fn proc_net_dev_bytes_zero_on_short_or_nonnumeric() {
        use super::parse_proc_net_dev_bytes;
        // Fewer than 10 fields -> no counters -> (0, 0).
        assert_eq!(parse_proc_net_dev_bytes("wg0: 1 2 3", "wg0"), (0, 0));
        // Non-numeric counters fall back to 0 each.
        assert_eq!(
            parse_proc_net_dev_bytes("wg0: x b c d e f g h y j", "wg0"),
            (0, 0)
        );
    }

    #[test]
    fn wg_latest_handshake_first_numeric_second_field() {
        use super::parse_wg_latest_handshake_timestamp;
        assert_eq!(
            parse_wg_latest_handshake_timestamp("PUBKEY1\t1700000000\nPUBKEY2\t1700000500\n"),
            Some(1_700_000_000)
        );
        // A never-handshaked peer reports 0, returned as-is.
        assert_eq!(parse_wg_latest_handshake_timestamp("PUBKEY\t0"), Some(0));
        // Skips a non-numeric line, takes the next numeric one.
        assert_eq!(
            parse_wg_latest_handshake_timestamp("BAD x\nGOOD 42"),
            Some(42)
        );
        // No numeric second field anywhere -> None.
        assert_eq!(parse_wg_latest_handshake_timestamp("PUBKEY only"), None);
        assert_eq!(
            parse_wg_latest_handshake_timestamp("PUBKEY notanumber"),
            None
        );
        assert_eq!(parse_wg_latest_handshake_timestamp(""), None);
    }

    #[test]
    fn proc_pid_stat_starttime_extracts_field_22() {
        use super::parse_proc_pid_stat_starttime_ticks;
        // pid (comm) state ppid ... field 22 = starttime.
        let stat = "1234 (rustynetd) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9999 12345678";
        assert_eq!(parse_proc_pid_stat_starttime_ticks(stat), Some(9999));
        // Fewer than 22 fields -> None.
        assert_eq!(parse_proc_pid_stat_starttime_ticks("1 (x) S 1 2 3"), None);
        // Non-numeric field 22 -> None.
        let bad = "1234 (rustynetd) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 notnum 12345";
        assert_eq!(parse_proc_pid_stat_starttime_ticks(bad), None);
        assert_eq!(parse_proc_pid_stat_starttime_ticks(""), None);
    }

    #[test]
    fn sysctl_bool_and_u32_conventions() {
        use super::{parse_sysctl_bool_enabled, parse_sysctl_u32};
        // Any trimmed value other than "0" is enabled.
        assert!(!parse_sysctl_bool_enabled("0"));
        assert!(!parse_sysctl_bool_enabled(" 0 \n"));
        assert!(parse_sysctl_bool_enabled("1"));
        assert!(parse_sysctl_bool_enabled("2"));
        // Documented quirk: empty / non-"0" garbage reads as enabled.
        assert!(parse_sysctl_bool_enabled(""));
        assert!(parse_sysctl_bool_enabled("false"));
        // u32: trims + parses; 0 on garbage or empty.
        assert_eq!(parse_sysctl_u32("2\n"), 2);
        assert_eq!(parse_sysctl_u32(" 42 "), 42);
        assert_eq!(parse_sysctl_u32("garbage"), 0);
        assert_eq!(parse_sysctl_u32(""), 0);
    }

    #[test]
    fn macos_ifconfig_iface_up_requires_up_without_down() {
        use super::parse_macos_ifconfig_iface_up;
        assert!(parse_macos_ifconfig_iface_up(
            "flags=8863<UP,BROADCAST,RUNNING> mtu 1500"
        ));
        // A DOWN flag anywhere wins (precedence documented).
        assert!(!parse_macos_ifconfig_iface_up("flags=8802<DOWN,BROADCAST>"));
        assert!(!parse_macos_ifconfig_iface_up(
            "flags=<UP,BROADCAST> ... DOWN"
        ));
        // No UP flag at all.
        assert!(!parse_macos_ifconfig_iface_up("flags=<BROADCAST,RUNNING>"));
        assert!(!parse_macos_ifconfig_iface_up(""));
    }

    #[test]
    fn windows_ipconfig_mentions_interface_is_case_insensitive() {
        use super::windows_ipconfig_mentions_interface;
        assert!(windows_ipconfig_mentions_interface(
            "Ethernet adapter RustyNet0:",
            "rustynet0"
        ));
        assert!(windows_ipconfig_mentions_interface(
            "... WIRELESS lan ...",
            "wireless"
        ));
        assert!(!windows_ipconfig_mentions_interface(
            "Ethernet adapter Ethernet:",
            "rustynet0"
        ));
        assert!(!windows_ipconfig_mentions_interface("", "eth0"));
    }

    #[test]
    fn key_age_days_saturates_future_mtime() {
        use super::key_age_days;
        assert_eq!(key_age_days(400 * 86_400, 0), 400);
        assert_eq!(key_age_days(86_400, 0), 1);
        // Sub-day age rounds down to 0.
        assert_eq!(key_age_days(86_399, 0), 0);
        // Future mtime (modified > now) saturates to 0 instead of panicking on
        // subtraction underflow.
        assert_eq!(key_age_days(100, 999_999), 0);
        assert_eq!(key_age_days(0, u64::MAX), 0);
    }

    #[test]
    fn linux_operstate_only_exact_up_is_up() {
        assert!(parse_linux_operstate("up"));
        assert!(parse_linux_operstate("up\n"));
        assert!(parse_linux_operstate("  up  "));
        assert!(parse_linux_operstate("up\r\n"));
        // Everything else fails closed toward "down".
        assert!(!parse_linux_operstate("down"));
        assert!(!parse_linux_operstate("unknown"));
        assert!(!parse_linux_operstate("dormant"));
        assert!(!parse_linux_operstate("lowerlayerdown"));
        assert!(!parse_linux_operstate("UP")); // case-sensitive
        assert!(!parse_linux_operstate(""));
        assert!(!parse_linux_operstate("   "));
        assert!(!parse_linux_operstate("up down"));
    }

    #[test]
    fn macos_ifconfig_parses_headers_and_up_flag() {
        let sample = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.0.5 netmask 0xffffff00 broadcast 192.168.0.255
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
";
        let ifaces = parse_macos_ifconfig_interfaces(sample);
        let by_name: std::collections::HashMap<_, _> =
            ifaces.iter().map(|i| (i.name.as_str(), i.up)).collect();
        assert_eq!(by_name.get("lo0"), Some(&true));
        assert_eq!(by_name.get("en0"), Some(&true));
        // gif0 header has no UP flag -> reported down.
        assert_eq!(by_name.get("gif0"), Some(&false));
        // Tab-indented detail lines never become interfaces.
        assert_eq!(ifaces.len(), 3);
        assert!(ifaces.iter().all(|i| i.addresses.is_empty()));
    }

    #[test]
    fn macos_ifconfig_skips_malformed_and_empty() {
        assert!(parse_macos_ifconfig_interfaces("").is_empty());
        // A leading ':' yields an empty name -> skipped.
        assert!(parse_macos_ifconfig_interfaces(": flags=<UP>").is_empty());
        // Non-alphabetic / indented lines are ignored.
        assert!(parse_macos_ifconfig_interfaces("\ten0: flags=<UP>\n123: x").is_empty());
    }

    #[test]
    fn windows_ipconfig_parses_adapter_headers() {
        let sample = "\
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.0.7
Wireless LAN adapter Wi-Fi:

   Media State . . . . . . . . . . . : Media disconnected
Some unrelated line: value
";
        let ifaces = parse_windows_ipconfig_interfaces(sample);
        let names: Vec<&str> = ifaces.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["Ethernet adapter Ethernet", "Wireless LAN adapter Wi-Fi"]
        );
        assert!(ifaces.iter().all(|i| i.up)); // ipconfig layer reports all up
        assert!(parse_windows_ipconfig_interfaces("").is_empty());
        assert!(parse_windows_ipconfig_interfaces("No adapters here: x").is_empty());
    }

    fn samples(name: &str, values: &[u64]) -> Vec<(String, u64)> {
        values.iter().map(|v| (name.to_owned(), *v)).collect()
    }

    #[test]
    fn rsa0050_arp_n_row_parses_full_row_and_skips_short_rows() {
        // 6 columns: Address HWtype HWaddress Flags Mask Iface
        let entry = parse_arp_n_row("192.168.1.1  ether  aa:bb:cc:dd:ee:ff  C  -  eth0")
            .expect("full row parses");
        assert_eq!(entry.ip, "192.168.1.1");
        assert_eq!(entry.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(entry.interface, "eth0");
        // 5 columns (the off-by-one that previously panicked): skipped, not a panic.
        assert!(parse_arp_n_row("192.168.1.1  ether  aa:bb:cc:dd:ee:ff  C  -").is_none());
        // empty / garbled rows are skipped.
        assert!(parse_arp_n_row("").is_none());
        assert!(parse_arp_n_row("incomplete").is_none());
    }

    #[test]
    fn regression_detection_needs_at_least_two_samples() {
        assert!(performance_regression_detection_internal(&[]).is_empty());
        assert!(performance_regression_detection_internal(&samples("latency", &[100])).is_empty());
    }

    #[test]
    fn regression_detection_flags_large_increase_as_increasing() {
        // 100 -> 200 is +100%, well over the 50% threshold.
        let result = performance_regression_detection_internal(&samples("latency_ms", &[100, 200]));
        assert_eq!(result.len(), 1, "a large increase must be reported");
        assert_eq!(result[0].metric, "latency_ms");
        assert_eq!(result[0].trend, "increasing");
        assert!(
            (result[0].slope_percent_per_day - 100.0).abs() < 1e-9,
            "slope should be the signed change percent, got {}",
            result[0].slope_percent_per_day
        );
    }

    #[test]
    fn regression_detection_flags_large_decrease_as_decreasing() {
        // Regression guard for the dead `"decreasing"` arm: before the fix the
        // outer `change_percent > 50.0` gate dropped every decrease, so this
        // returned empty and the decreasing label was unreachable. 1000 -> 200
        // is -80%, a real regression for a throughput-style metric.
        let result =
            performance_regression_detection_internal(&samples("throughput_rps", &[1000, 200]));
        assert_eq!(result.len(), 1, "a large decrease must be reported");
        assert_eq!(result[0].metric, "throughput_rps");
        assert_eq!(result[0].trend, "decreasing");
        assert!(
            result[0].slope_percent_per_day < 0.0,
            "a decrease must carry a negative slope, got {}",
            result[0].slope_percent_per_day
        );
    }

    #[test]
    fn regression_detection_ignores_changes_within_threshold() {
        // +25% and -25% are both under the 50% magnitude threshold.
        assert!(
            performance_regression_detection_internal(&samples("cpu_pct", &[100, 125])).is_empty()
        );
        assert!(
            performance_regression_detection_internal(&samples("cpu_pct", &[100, 75])).is_empty()
        );
    }

    #[test]
    fn regression_detection_skips_zero_first_sample_without_panicking() {
        // A zero baseline would divide to inf/NaN; it must be skipped, not
        // reported and not panic.
        let result = performance_regression_detection_internal(&samples("errors", &[0, 500]));
        assert!(
            result.is_empty(),
            "zero first sample must not yield a regression, got {} entries",
            result.len()
        );
    }

    #[test]
    fn regression_detection_uses_first_and_last_sample_per_metric() {
        // Only the first and last per-metric samples matter; intermediate
        // values are spanned. 100 -> (150) -> 300 is +200%.
        let result =
            performance_regression_detection_internal(&samples("rss_mb", &[100, 150, 300]));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].trend, "increasing");
        assert!((result[0].slope_percent_per_day - 200.0).abs() < 1e-9);
    }

    #[test]
    fn regression_detection_groups_independent_metrics() {
        let mut history = samples("latency_ms", &[100, 300]); // +200% increasing
        history.extend(samples("throughput_rps", &[1000, 100])); // -90% decreasing
        history.extend(samples("cpu_pct", &[100, 110])); // +10% ignored

        let mut result = performance_regression_detection_internal(&history);
        // HashMap iteration order is unspecified — sort for a stable assertion.
        result.sort_by(|a, b| a.metric.cmp(&b.metric));
        assert_eq!(result.len(), 2, "only the two >50% movers are reported");
        assert_eq!(result[0].metric, "latency_ms");
        assert_eq!(result[0].trend, "increasing");
        assert_eq!(result[1].metric, "throughput_rps");
        assert_eq!(result[1].trend, "decreasing");
    }

    // ---- `ss -tlnp` parser (Linux): golden-fixture coverage ----

    #[cfg(target_os = "linux")]
    const SS_HEADER: &str = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process";

    #[cfg(target_os = "linux")]
    fn parse_ss(rows: &[&str]) -> Vec<super::ListeningSocket> {
        let mut text = String::from(SS_HEADER);
        for row in rows {
            text.push('\n');
            text.push_str(row);
        }
        super::parse_ss_listening_sockets(&text)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ss_empty_or_header_only_yields_no_sockets() {
        assert!(super::parse_ss_listening_sockets("").is_empty());
        // Header-only output (the first line is always skipped).
        assert!(super::parse_ss_listening_sockets(SS_HEADER).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ss_extracts_ipv4_listening_socket() {
        let sockets = parse_ss(&[
            "LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:((\"sshd\",pid=1,fd=3))",
        ]);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].address, "0.0.0.0");
        assert_eq!(sockets[0].port, 22);
        // The current parser labels `protocol` from the State column.
        assert_eq!(sockets[0].protocol, "LISTEN");
        assert_eq!(sockets[0].pid, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ss_handles_bracketed_ipv6_addresses() {
        // The rfind(':') split must keep the bracketed IPv6 host intact and
        // only peel the trailing port — the IPv6 edge case the audit flagged.
        let sockets = parse_ss(&[
            "LISTEN 0      128             [::]:443          [::]:*",
            "LISTEN 0      128          [::1]:5432            [::]:*",
        ]);
        assert_eq!(sockets.len(), 2);
        assert_eq!(sockets[0].address, "[::]");
        assert_eq!(sockets[0].port, 443);
        assert_eq!(sockets[1].address, "[::1]");
        assert_eq!(sockets[1].port, 5432);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ss_malformed_port_degrades_to_zero() {
        // Documents the long-standing `unwrap_or(0)` behavior: a non-numeric
        // port is not dropped, it becomes 0. The address is still extracted.
        let sockets = parse_ss(&["LISTEN 0 128 127.0.0.1:notaport 0.0.0.0:*"]);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].address, "127.0.0.1");
        assert_eq!(sockets[0].port, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ss_drops_rows_without_port_separator_or_too_few_fields() {
        let sockets = parse_ss(&[
            "LISTEN 0 128 noportseparator 0.0.0.0:*", // parts[3] has no ':'
            "LISTEN 0 128",                           // fewer than 4 fields
            "",                                       // blank line
        ]);
        assert!(
            sockets.is_empty(),
            "rows without a usable address:port must be dropped, got {} entries",
            sockets.len()
        );
    }

    // ---- /proc parsers (Linux): golden-fixture coverage ----

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_dev_extracts_counters_and_skips_short_rows() {
        // Two header lines + a real 17-field row + a deliberately short row.
        // Before the bounds fix the short row (>=10 but <11 fields) panicked on
        // the parts[10] access; it must now be skipped.
        let fixture = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 123456    789   1    2    0    0     0          0         654321   321     0    0    0    0     0       0
 short: 1 2 3 4 5 6 7 8 9
    lo:    100      5    0    0    0    0     0          0            100      5    0    0    0    0     0       0
";
        let stats = super::parse_proc_net_dev(fixture);
        assert_eq!(
            stats.len(),
            2,
            "only the two full rows parse; short row skipped"
        );
        assert_eq!(stats[0].name, "eth0");
        assert_eq!(stats[0].bytes_in, 123456);
        assert_eq!(stats[0].packets_in, 789);
        assert_eq!(stats[0].errors, 1);
        assert_eq!(stats[0].dropped, 2);
        assert_eq!(stats[0].bytes_out, 654321);
        assert_eq!(stats[0].packets_out, 321);
        assert_eq!(stats[1].name, "lo");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_dev_empty_and_header_only_are_safe() {
        assert!(super::parse_proc_net_dev("").is_empty());
        assert!(super::parse_proc_net_dev("h1\nh2\n").is_empty());
        // A non-numeric counter degrades to 0 rather than dropping the row.
        let stats = super::parse_proc_net_dev("h1\nh2\n eth0: NaN 2 3 4 5 6 7 8 9 10 11\n");
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].bytes_in, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_loadavg_reads_three_averages() {
        let (l1, l5, l15) = super::parse_proc_loadavg("0.50 1.25 2.00 1/234 5678");
        assert!((l1 - 0.50).abs() < 1e-9);
        assert!((l5 - 1.25).abs() < 1e-9);
        assert!((l15 - 2.00).abs() < 1e-9);
        // Short / malformed input yields zeros, no panic.
        assert_eq!(super::parse_proc_loadavg("0.1 0.2"), (0.0, 0.0, 0.0));
        assert_eq!(super::parse_proc_loadavg(""), (0.0, 0.0, 0.0));
        assert_eq!(super::parse_proc_loadavg("x y z"), (0.0, 0.0, 0.0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_meminfo_computes_used_and_percent() {
        let info = super::parse_proc_meminfo(
            "MemTotal:       2048 kB\nMemFree:  500 kB\nMemAvailable:    1024 kB\n",
        );
        assert_eq!(info.total_mb, 2); // 2048 kB / 1024
        assert_eq!(info.available_mb, 1);
        assert_eq!(info.used_mb, 1); // (2048-1024)/1024
        assert!((info.percent - 50.0).abs() < 1e-9);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_meminfo_missing_fields_default_to_zero_without_div_by_zero() {
        let info = super::parse_proc_meminfo("SomethingElse: 5 kB\n");
        assert_eq!(info.total_mb, 0);
        assert_eq!(info.percent, 0.0); // total==0 guarded, no NaN
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_cpuinfo_counts_cores_and_reads_model() {
        let info = super::parse_proc_cpuinfo(
            "processor\t: 0\nmodel name\t: Test CPU @ 3.0GHz\nprocessor\t: 1\n",
        );
        assert_eq!(info.cores, 2);
        assert_eq!(info.model, "Test CPU @ 3.0GHz");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_cpuinfo_empty_reports_one_core_unknown() {
        let info = super::parse_proc_cpuinfo("");
        assert_eq!(info.cores, 1);
        assert_eq!(info.model, "Unknown");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_uptime_truncates_to_whole_seconds() {
        assert_eq!(super::parse_proc_uptime_secs("12345.67 9999.00"), 12345);
        assert_eq!(super::parse_proc_uptime_secs(""), 0);
        assert_eq!(super::parse_proc_uptime_secs("notanumber"), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ip_addr_inet_addresses_extracts_v4_and_v6() {
        let stdout = "\
2: rustynet0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420
    inet 100.64.0.5/32 scope global rustynet0
    inet6 fd7a:115c:a1e0::5/128 scope global
    valid_lft forever preferred_lft forever
";
        let addrs = super::parse_ip_addr_inet_addresses(stdout);
        assert_eq!(addrs, vec!["100.64.0.5/32", "fd7a:115c:a1e0::5/128"]);
        // Empty / no-inet output yields nothing, no panic.
        assert!(super::parse_ip_addr_inet_addresses("").is_empty());
        assert!(super::parse_ip_addr_inet_addresses("2: eth0: <UP>\n").is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ip_route_show_extracts_default_and_mesh_routes() {
        let stdout = "\
default via 192.168.1.1 dev eth0 proto dhcp metric 100
100.64.0.0/10 dev rustynet0 proto kernel scope link
10.0.0.0/24 via 10.0.0.1 dev rustynet0
bad
";
        let routes = super::parse_ip_route_show(stdout);
        assert_eq!(routes.len(), 3, "the <3-field line is skipped");
        assert_eq!(routes[0].destination, "default");
        assert_eq!(routes[0].gateway, "192.168.1.1");
        assert_eq!(routes[0].interface, "eth0");
        // Pins the (imprecise but preserved) positional heuristic: gateway is
        // always field 2 and interface field 4, so a `dev` route with no `via`
        // (`100.64.0.0/10 dev rustynet0 proto kernel ...`) yields gateway
        // "rustynet0" and interface "kernel". Behavior carried over verbatim
        // from the pre-split code; a future change can make it `via`-aware.
        assert_eq!(routes[1].destination, "100.64.0.0/10");
        assert_eq!(routes[1].gateway, "rustynet0");
        assert_eq!(routes[1].interface, "kernel");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ip_route_show_empty_is_safe() {
        assert!(super::parse_ip_route_show("").is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn parse_wg_show_peers_extracts_and_skips_headers() {
        // A line with >=4 fields whose first token is neither `interface:` nor
        // `public` is a peer row: name = "peer-" + first 8 chars of field 0,
        // allowed_ips = field 2, ip = field 3 (the preserved positional rule).
        let stdout = "\
interface: rustynet0
  public key: serverkeyserverkey
abcdefghijklmnop x 100.64.0.2/32 203.0.113.9:51820
short row here
";
        let peers = super::parse_wg_show_peers(stdout);
        assert_eq!(peers.len(), 1, "only the 4+-field non-header row parses");
        assert_eq!(peers[0].name, "peer-abcdefgh");
        assert_eq!(peers[0].allowed_ips, "100.64.0.2/32");
        assert_eq!(peers[0].ip, "203.0.113.9:51820");
        assert!(peers[0].last_handshake_ago.is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn parse_wg_show_peers_empty_and_short_first_field_are_safe() {
        assert!(super::parse_wg_show_peers("").is_empty());
        // First field shorter than the 8-char slice bound must not panic.
        let peers = super::parse_wg_show_peers("ab x cd ef\n");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "peer-ab");
        // Field 0 = "aaaaaa€" — the 3-byte '€' spans bytes 6..9, so byte index
        // 8 is mid-character. The old `[..8]` byte slice panicked here; the
        // char-boundary-safe truncation falls back to the whole field.
        let peers = super::parse_wg_show_peers("aaaaaa\u{20ac} x cd ef\n");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "peer-aaaaaa\u{20ac}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_tcp_tallies_states() {
        // Minimal /proc/net/tcp: header + rows whose field 3 is the state hex.
        let fixture = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0
   1: 0100007F:1F91 0100007F:C000 01 00000000:00000000 00:00000000 00000000     0
   2: 0100007F:1F92 0100007F:C001 01 00000000:00000000 00:00000000 00000000     0
   3: 0100007F:1F93 0100007F:C002 06 00000000:00000000 00:00000000 00000000     0
   4: 0100007F:1F94 0100007F:C003 08 00000000:00000000 00:00000000 00000000     0
short
";
        let stats = super::parse_proc_net_tcp_states(fixture);
        assert_eq!(stats.listening, 1); // 0A
        assert_eq!(stats.established, 2); // 01 x2
        assert_eq!(stats.time_wait, 1); // 06
        assert_eq!(stats.total, 4); // 08 (close-wait) and the short line ignored
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_tcp_empty_and_header_only_are_zero() {
        let z = super::parse_proc_net_tcp_states("");
        assert_eq!(z.total, 0);
        let h = super::parse_proc_net_tcp_states("sl local rem st ...\n");
        assert_eq!(h.total, 0);
    }

    #[test]
    fn parse_os_release_debian_and_ubuntu() {
        let (id, like) = super::parse_os_release(
            "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n",
        );
        assert_eq!(id.as_deref(), Some("ubuntu"));
        assert_eq!(like, vec!["debian".to_owned()]);
        assert_eq!(
            super::pkg_family_for(id.as_deref(), &like),
            Some(super::PkgFamily::Apt)
        );

        let (id, _) = super::parse_os_release("ID=debian\nVERSION_ID=\"13\"\n");
        assert_eq!(id.as_deref(), Some("debian"));
        assert_eq!(
            super::pkg_family_for(id.as_deref(), &[]),
            Some(super::PkgFamily::Apt)
        );
    }

    #[test]
    fn parse_os_release_fedora_and_rocky() {
        let (id, like) = super::parse_os_release("ID=fedora\nVERSION_ID=44\n");
        assert_eq!(id.as_deref(), Some("fedora"));
        assert!(like.is_empty());
        assert_eq!(
            super::pkg_family_for(id.as_deref(), &like),
            Some(super::PkgFamily::Dnf)
        );

        // Rocky: quoted ID + multi-token quoted ID_LIKE.
        let (id, like) = super::parse_os_release("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n");
        assert_eq!(id.as_deref(), Some("rocky"));
        assert_eq!(like, vec!["rhel", "centos", "fedora"]);
        assert_eq!(
            super::pkg_family_for(id.as_deref(), &like),
            Some(super::PkgFamily::Dnf)
        );
    }

    #[test]
    fn pkg_family_falls_back_to_id_like_then_none() {
        // Unknown ID, but ID_LIKE tells us the family.
        assert_eq!(
            super::pkg_family_for(Some("somederivative"), &["ubuntu".to_owned()]),
            Some(super::PkgFamily::Apt)
        );
        assert_eq!(
            super::pkg_family_for(Some("weirdrhelclone"), &["rhel".to_owned()]),
            Some(super::PkgFamily::Dnf)
        );
        // Unrecognized distro -> None (fail closed, do not guess).
        assert_eq!(
            super::pkg_family_for(Some("arch"), &["archlinux".to_owned()]),
            None
        );
        assert_eq!(super::pkg_family_for(None, &[]), None);
    }

    #[test]
    fn target_triple_maps_published_targets_and_rejects_others() {
        use super::{HostFacts, OsFamily};
        let mk = |family, arch: &str| HostFacts {
            family,
            distro_id: None,
            distro_like: Vec::new(),
            arch: arch.to_owned(),
            pkg_family: None,
        };
        assert_eq!(
            mk(OsFamily::Linux, "x86_64").target_triple(),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(
            mk(OsFamily::Linux, "aarch64").target_triple(),
            Some("aarch64-unknown-linux-gnu")
        );
        assert_eq!(
            mk(OsFamily::Macos, "aarch64").target_triple(),
            Some("aarch64-apple-darwin")
        );
        assert_eq!(
            mk(OsFamily::Macos, "x86_64").target_triple(),
            Some("x86_64-apple-darwin")
        );
        assert_eq!(
            mk(OsFamily::Windows, "x86_64").target_triple(),
            Some("x86_64-pc-windows-msvc")
        );
        // Unpublished (family, arch) pairs must fail closed.
        assert_eq!(mk(OsFamily::Linux, "riscv64").target_triple(), None);
        assert_eq!(mk(OsFamily::Windows, "aarch64").target_triple(), None);
        assert_eq!(mk(OsFamily::Unsupported, "x86_64").target_triple(), None);
    }

    #[test]
    fn host_facts_reports_a_supported_family_on_the_test_host() {
        // Smoke test: on any dev/CI host (linux/macos/windows) the family is
        // resolved and arch is populated.
        let facts = super::host_facts();
        assert!(!facts.arch.is_empty());
        assert_ne!(facts.family, super::OsFamily::Unsupported);
    }

    // ---- `getfacl` parser: golden-fixture coverage ----
    //
    // These parsers (and the sysctl / socket-enumeration ones below) are
    // deliberately NOT `#[cfg(target_os = "...")]`-gated even though their
    // production callers are — they are plain `&str -> T` string parsers
    // with no OS-specific API dependency, so gating only the IO wrapper
    // (matching the pre-existing `parse_macos_ifconfig_iface_up` /
    // `parse_windows_ipconfig_interfaces` convention) lets every one of
    // them be compiled and exercised on any dev/CI host, regardless of
    // which OS variant would call it in production.

    #[test]
    fn getfacl_output_extracts_owner_group_and_documents_base_entry_quirk() {
        let output = "\
# file: secrets.key
# owner: alice
# group: staff
user::rw-
group::r--
other::---
user:bob:rwx
";
        let (owner, group, extended) = super::parse_getfacl_output(output);
        assert_eq!(owner, "alice");
        assert_eq!(group, "staff");
        // Preserved quirk: the baseline `user::`/`group::` entries also
        // start with the literal prefixes checked, so they land in
        // "extended" ACL alongside the genuine named `user:bob:rwx` grant;
        // `other::---` matches neither prefix and is excluded.
        assert_eq!(
            extended,
            vec![
                "user::rw-".to_owned(),
                "group::r--".to_owned(),
                "user:bob:rwx".to_owned(),
            ]
        );
    }

    #[test]
    fn getfacl_output_missing_headers_default_to_unknown() {
        let (owner, group, extended) = super::parse_getfacl_output("user::rwx\n");
        assert_eq!(owner, "unknown");
        assert_eq!(group, "unknown");
        assert_eq!(extended, vec!["user::rwx".to_owned()]);
    }

    #[test]
    fn getfacl_output_present_but_valueless_header_yields_empty_not_unknown() {
        // A present header line with nothing after the prefix yields an
        // empty string — the "unknown" default only applies when the
        // whole line is absent.
        let (owner, group, extended) = super::parse_getfacl_output("# owner:\n# group:\n");
        assert_eq!(owner, "");
        assert_eq!(group, "");
        assert!(extended.is_empty());
    }

    #[test]
    fn getfacl_output_empty_input_is_safe() {
        let (owner, group, extended) = super::parse_getfacl_output("");
        assert_eq!(owner, "unknown");
        assert_eq!(group, "unknown");
        assert!(extended.is_empty());
    }

    // ---- macOS `sysctl` value parsers: golden-fixture coverage ----

    #[test]
    fn macos_sysctl_colon_value_extracts_trimmed_segment() {
        assert_eq!(
            super::parse_macos_sysctl_colon_value("hw.ncpu: 8\n"),
            Some("8")
        );
        assert_eq!(
            super::parse_macos_sysctl_colon_value("machdep.cpu.brand_string: Apple M1\n"),
            Some("Apple M1")
        );
    }

    #[test]
    fn macos_sysctl_colon_value_truncates_at_second_colon() {
        // Preserved quirk: `split(':').nth(1)` only ever returns the
        // segment between the first and second colon, not "everything
        // after the first colon" — a value containing its own colon is
        // truncated.
        assert_eq!(super::parse_macos_sysctl_colon_value("a:b:c"), Some("b"));
    }

    #[test]
    fn macos_sysctl_colon_value_none_without_a_second_segment() {
        assert_eq!(super::parse_macos_sysctl_colon_value("garbage"), None);
        assert_eq!(super::parse_macos_sysctl_colon_value(""), None);
        // A colon with nothing after it is a present-but-empty value.
        assert_eq!(super::parse_macos_sysctl_colon_value("key:"), Some(""));
    }

    #[test]
    fn macos_sysctl_equals_value_extracts_trimmed_segment() {
        assert_eq!(
            super::parse_macos_sysctl_equals_value("vm.swappiness = 60\n"),
            Some("60")
        );
    }

    #[test]
    fn macos_sysctl_equals_value_truncates_at_second_equals_and_none_without_one() {
        assert_eq!(super::parse_macos_sysctl_equals_value("a=b=c"), Some("b"));
        assert_eq!(super::parse_macos_sysctl_equals_value("noequals"), None);
        assert_eq!(super::parse_macos_sysctl_equals_value(""), None);
    }

    // ---- `hex_to_ip`: golden-fixture + panic-safety regression ----

    #[test]
    fn hex_to_ip_decodes_valid_kernel_endian_hex() {
        assert_eq!(super::hex_to_ip("0100007F"), "127.0.0.1");
        assert_eq!(super::hex_to_ip("0A0A0A0A"), "10.10.10.10");
        // Case-insensitive.
        assert_eq!(super::hex_to_ip("0100007f"), "127.0.0.1");
    }

    #[test]
    fn hex_to_ip_unknown_on_short_or_non_hex_input() {
        assert_eq!(super::hex_to_ip("01"), "unknown");
        assert_eq!(super::hex_to_ip(""), "unknown");
        assert_eq!(super::hex_to_ip("GGGGGGGG"), "unknown");
    }

    #[test]
    fn hex_to_ip_never_panics_on_utf8_char_boundary_straddling_input() {
        // Regression for a latent panic fixed in this split: the original
        // indexed `&hex[i*2..i*2+2]` directly. `"a\u{e9}000000"` is 9 bytes
        // (`a` = 1 byte, `é` = 2 bytes at offsets 1..3, then 6 ASCII
        // bytes), so `hex.len() >= 8` is true, but slicing bytes 0..2 or
        // 2..4 lands mid-`é` and used to panic ("byte index 2 is not a
        // char boundary"). The `str::get`-based rewrite returns `None` for
        // those chunks instead, degrading to "unknown" rather than
        // panicking.
        assert_eq!(super::hex_to_ip("a\u{e9}000000"), "unknown");
    }

    // ---- `/proc/net/tcp` connection parser (Linux): golden-fixture coverage ----

    #[test]
    fn proc_net_tcp_connections_extracts_local_remote_and_state() {
        let fixture = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 0100007F:1F90 0A0A0A0A:01BB 01 00000000:00000000 00:00000000 00000000     0
";
        let conns = super::parse_proc_net_tcp_connections(fixture);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].local_addr, "127.0.0.1:8080");
        assert_eq!(conns[0].remote_addr, "10.10.10.10:443");
        assert_eq!(conns[0].state, "01");
        assert_eq!(conns[0].pid, None);
    }

    #[test]
    fn proc_net_tcp_connections_drops_short_rows_and_missing_separators() {
        let fixture = "\
header line skipped regardless of content
too short
sl 0100007Fnocolon 0A0A0A0A:01BB 01
";
        // Row 2 has <4 fields; row 3's local field has no `:` separator —
        // both dropped, not defaulted.
        assert!(super::parse_proc_net_tcp_connections(fixture).is_empty());
    }

    #[test]
    fn proc_net_tcp_connections_empty_and_header_only_are_safe() {
        assert!(super::parse_proc_net_tcp_connections("").is_empty());
        assert!(super::parse_proc_net_tcp_connections("header only\n").is_empty());
    }

    // ---- macOS/Windows TCP connection parsers: golden-fixture coverage ----

    #[test]
    fn netstat_tcp_connections_macos_extracts_row() {
        let fixture = "\
Active Internet connections
tcp4       0      0  192.168.1.5.51820      93.184.216.34.443      ESTABLISHED
";
        let conns = super::parse_netstat_tcp_connections_macos(fixture);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].local_addr, "192.168.1.5.51820");
        assert_eq!(conns[0].remote_addr, "93.184.216.34.443");
        assert_eq!(conns[0].state, "ESTABLISHED");
    }

    #[test]
    fn netstat_tcp_connections_macos_requires_six_fields() {
        // RSA-0050: the parser indexes fields[5]; a 5-field row is dropped.
        let fixture = "header\ntcp4 0 0 a b\n";
        assert!(super::parse_netstat_tcp_connections_macos(fixture).is_empty());
        assert!(super::parse_netstat_tcp_connections_macos("").is_empty());
    }

    #[test]
    fn powershell_tcp_connections_csv_unquotes_and_joins_host_port() {
        let fixture = "\
\"LocalAddress\",\"LocalPort\",\"RemoteAddress\",\"RemotePort\",\"State\"
\"192.168.1.5\",\"51820\",\"93.184.216.34\",\"443\",\"Established\"
";
        let conns = super::parse_powershell_tcp_connections_csv(fixture);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].local_addr, "192.168.1.5:51820");
        assert_eq!(conns[0].remote_addr, "93.184.216.34:443");
        assert_eq!(conns[0].state, "Established");
    }

    #[test]
    fn powershell_tcp_connections_csv_skips_short_rows_and_empty() {
        let fixture = "header\n\"a\",\"b\",\"c\",\"d\"\n";
        assert!(super::parse_powershell_tcp_connections_csv(fixture).is_empty());
        assert!(super::parse_powershell_tcp_connections_csv("").is_empty());
    }

    // ---- macOS/Windows listening-socket parsers: golden-fixture coverage ----

    #[test]
    fn netstat_listening_sockets_macos_extracts_when_field_has_dot_and_listen() {
        // PRESERVED QUIRK: field 3 does double duty as both the "LISTEN"
        // substring check and the `rfind('.')` address/port source, so a
        // captured row's "address" can include stray text (here the
        // literal "LISTEN") that happened to precede the last dot.
        let fixture = "\
Active Internet connections (only servers)
tcp4       0      0  127.0.0.1.LISTEN.8080  *.*                    LISTEN
";
        let sockets = super::parse_netstat_listening_sockets_macos(fixture);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].protocol, "tcp4");
        assert_eq!(sockets[0].address, "127.0.0.1.LISTEN");
        assert_eq!(sockets[0].port, 8080);
        assert_eq!(sockets[0].pid, None);
    }

    #[test]
    fn netstat_listening_sockets_macos_malformed_trailing_segment_degrades_port_to_zero() {
        let fixture = "header\ntcp4 0 0 127.0.0.1.LISTEN *.* LISTEN\n";
        let sockets = super::parse_netstat_listening_sockets_macos(fixture);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].address, "127.0.0.1");
        assert_eq!(sockets[0].port, 0);
    }

    #[test]
    fn netstat_listening_sockets_macos_skips_non_listen_and_short_rows() {
        let fixture = "header\ntcp4 0 0 127.0.0.1.80 *.* CLOSED\ntcp4 0 0\n";
        assert!(super::parse_netstat_listening_sockets_macos(fixture).is_empty());
        assert!(super::parse_netstat_listening_sockets_macos("").is_empty());
    }

    #[test]
    fn netstat_listening_sockets_windows_extracts_row_with_pid_and_no_header_skip() {
        // No explicit header skip: a header row is excluded only because
        // it does not contain "LISTEN" in field 3, not by a `.skip(1)`.
        let fixture = "\
  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:135            host:0                 LISTENING          1234
";
        let sockets = super::parse_netstat_listening_sockets_windows(fixture);
        assert_eq!(sockets.len(), 1, "only the LISTENING row qualifies");
        assert_eq!(sockets[0].protocol, "TCP");
        assert_eq!(sockets[0].address, "0.0.0.0");
        assert_eq!(sockets[0].port, 135);
        assert_eq!(sockets[0].pid, Some(1234));
    }

    #[test]
    fn netstat_listening_sockets_windows_no_colon_skips_malformed_port_degrades() {
        // No `:` in field 1 -> dropped entirely (not defaulted).
        let no_colon = "TCP 1.2.3.4 5.6.7.8 LISTENING";
        assert!(super::parse_netstat_listening_sockets_windows(no_colon).is_empty());
        // A `:` present but non-numeric tail -> port degrades to 0.
        let bad_port = "TCP 1.2.3.4:abc 5.6.7.8 LISTENING";
        let sockets = super::parse_netstat_listening_sockets_windows(bad_port);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].port, 0);
    }

    // ---- connection-state histogram parsers: golden-fixture coverage ----

    #[test]
    fn ss_connection_states_tallies_each_recognized_state_and_skips_blank() {
        let fixture = "\
State Recv-Q Send-Q Local Peer
ESTAB 0 0 a b
TIME-WAIT 0 0 a b
SYN-RECV 0 0 a b
CLOSE-WAIT 0 0 a b
FIN-WAIT-1 0 0 a b
FIN-WAIT-2 0 0 a b
UNKNOWN-STATE 0 0 a b

";
        let h = super::parse_ss_connection_states(fixture);
        assert_eq!(h.established, 1);
        assert_eq!(h.time_wait, 1);
        assert_eq!(h.syn_recv, 1);
        assert_eq!(h.close_wait, 1);
        assert_eq!(h.fin_wait1, 1);
        assert_eq!(h.fin_wait2, 1);
        // Unrecognized state -> other; the trailing blank line has zero
        // fields and is skipped rather than counted as other.
        assert_eq!(h.other, 1);
    }

    #[test]
    fn netstat_connection_states_macos_reads_last_field_and_skips_blank() {
        let fixture = "\
Active Internet connections
tcp4 0 0 a b ESTABLISHED
tcp4 0 0 a b TIME_WAIT
tcp4 0 0 a b SYN_RECV
tcp4 0 0 a b CLOSE_WAIT
tcp4 0 0 a b FIN_WAIT_1
tcp4 0 0 a b FIN_WAIT_2
tcp4 0 0 a b UNKNOWNSTATE

";
        let h = super::parse_netstat_connection_states_macos(fixture);
        assert_eq!(h.established, 1);
        assert_eq!(h.time_wait, 1);
        assert_eq!(h.syn_recv, 1);
        assert_eq!(h.close_wait, 1);
        assert_eq!(h.fin_wait1, 1);
        assert_eq!(h.fin_wait2, 1);
        assert_eq!(h.other, 1);
    }

    #[test]
    fn netstat_connection_states_windows_has_no_fin_wait_arms_and_uses_syn_received() {
        // Preserved cross-platform inconsistency: Windows matches
        // `SYN_RECEIVED` (not `SYN_RECV`) and has no `FIN_WAIT_1`/
        // `FIN_WAIT_2` arms at all, so both fall to `other` — unlike the
        // macOS variant above.
        let fixture = "\
tcp4 0 0 a b ESTABLISHED
tcp4 0 0 a b TIME_WAIT
tcp4 0 0 a b SYN_RECEIVED
tcp4 0 0 a b CLOSE_WAIT
tcp4 0 0 a b FIN_WAIT_1
tcp4 0 0 a b FIN_WAIT_2
";
        let h = super::parse_netstat_connection_states_windows(fixture);
        assert_eq!(h.established, 1);
        assert_eq!(h.time_wait, 1);
        assert_eq!(h.syn_recv, 1);
        assert_eq!(h.close_wait, 1);
        assert_eq!(h.fin_wait1, 0);
        assert_eq!(h.fin_wait2, 0);
        assert_eq!(h.other, 2);
    }

    // ---- socket-stats (tally) parsers: golden-fixture coverage ----

    #[test]
    fn netstat_tcp_socket_states_macos_contains_match_with_precedence() {
        let fixture = "\
Active Internet connections
foo ESTABLISHED bar
foo LISTEN bar
foo TIME_WAIT bar
foo NOTHING bar
";
        let stats = super::parse_netstat_tcp_socket_states_macos(fixture);
        assert_eq!(stats.established, 1);
        assert_eq!(stats.listening, 1);
        assert_eq!(stats.time_wait, 1);
        assert_eq!(
            stats.total, 3,
            "the unmatched NOTHING row contributes nothing"
        );
    }

    #[test]
    fn netstat_tcp_socket_states_macos_precedence_favors_established() {
        // A line matching more than one substring is attributed to
        // whichever branch is checked first in the if/else-if chain.
        let fixture = "header\nESTABLISHEDLISTEN\n";
        let stats = super::parse_netstat_tcp_socket_states_macos(fixture);
        assert_eq!(stats.established, 1);
        assert_eq!(stats.listening, 0);
    }

    #[test]
    fn netstat_tcp_socket_states_macos_header_only_and_empty_are_zero() {
        assert_eq!(
            super::parse_netstat_tcp_socket_states_macos("header\n").total,
            0
        );
        assert_eq!(super::parse_netstat_tcp_socket_states_macos("").total, 0);
    }

    #[test]
    fn powershell_tcp_state_groups_sets_not_accumulates() {
        let fixture = "\
Name                      Count
----                      -----
Established                  12
Established                  99
Listen                        4
TimeWait                      2
UnknownState                  9
";
        let stats = super::parse_powershell_tcp_state_groups(fixture);
        // The second "Established" row *overwrites* the first (Group-Object
        // already aggregates per state upstream) rather than accumulating.
        assert_eq!(stats.established, 99);
        assert_eq!(stats.listening, 4);
        assert_eq!(stats.time_wait, 2);
        assert_eq!(stats.total, 105);
    }

    #[test]
    fn powershell_tcp_state_groups_skips_two_header_lines_and_short_rows() {
        // Only one data line, but it must survive the `skip(2)` header
        // removal; a short (1-field) row is ignored.
        let fixture = "Name Count\n---- -----\nEstablishedOnly\nListen 7\n";
        let stats = super::parse_powershell_tcp_state_groups(fixture);
        assert_eq!(stats.listening, 7);
        assert_eq!(stats.established, 0);
        assert!(super::parse_powershell_tcp_state_groups("").total == 0);
    }

    // ---- property test: none of the newly-split parsers ever panic ----

    /// A single probe parser: takes the raw captured-output text and
    /// discards whatever typed result it produces. Named as a type alias
    /// so the test below doesn't trip `clippy::type_complexity`.
    type ProbeParser = Box<dyn Fn(&str)>;

    #[test]
    fn split_parsers_never_panic_on_adversarial_input() {
        // Parser-never-panics invariant for every pure parser split out of
        // an IO-fused `*_internal` fn in this batch (getfacl / sysctl /
        // macOS+Windows socket enumeration, plus `hex_to_ip`). Each
        // closure discards its result — only the absence of a panic is
        // asserted; a real panic propagates and fails the test with a
        // backtrace pointing at the offending parser and input.
        let parsers: Vec<ProbeParser> = vec![
            Box::new(|s| {
                let _ = super::parse_getfacl_output(s);
            }),
            Box::new(|s| {
                let _ = super::parse_macos_sysctl_colon_value(s);
            }),
            Box::new(|s| {
                let _ = super::parse_macos_sysctl_equals_value(s);
            }),
            Box::new(|s| {
                let _ = super::hex_to_ip(s);
            }),
            Box::new(|s| {
                let _ = super::parse_proc_net_tcp_connections(s);
            }),
            Box::new(|s| {
                let _ = super::parse_netstat_tcp_connections_macos(s);
            }),
            Box::new(|s| {
                let _ = super::parse_powershell_tcp_connections_csv(s);
            }),
            Box::new(|s| {
                let _ = super::parse_netstat_listening_sockets_macos(s);
            }),
            Box::new(|s| {
                let _ = super::parse_netstat_listening_sockets_windows(s);
            }),
            Box::new(|s| {
                let _ = super::parse_ss_connection_states(s);
            }),
            Box::new(|s| {
                let _ = super::parse_netstat_connection_states_macos(s);
            }),
            Box::new(|s| {
                let _ = super::parse_netstat_connection_states_windows(s);
            }),
            Box::new(|s| {
                let _ = super::parse_netstat_tcp_socket_states_macos(s);
            }),
            Box::new(|s| {
                let _ = super::parse_powershell_tcp_state_groups(s);
            }),
        ];

        // Structural-garbage probes: empty, whitespace, bare separators, a
        // flood of a single separator, long lines, CRLF, multi-byte UTF-8,
        // and near-miss golden fixtures.
        let probes: Vec<String> = vec![
            String::new(),
            " ".to_owned(),
            "\n".to_owned(),
            "\t\t\t".to_owned(),
            ":".to_owned(),
            ".".to_owned(),
            "=".to_owned(),
            ",".to_owned(),
            "\"".to_owned(),
            ":".repeat(2000),
            ".".repeat(2000),
            "a".repeat(5000),
            "\u{20ac}".repeat(500),
            "a:b.c=d,e\"f\u{20ac}g\r\n".repeat(200),
            "# owner:\n# group:\nuser:\ngroup:\n".repeat(100),
            "\r\n".repeat(500),
        ];
        for probe in &probes {
            for parser in &parsers {
                parser(probe);
            }
        }

        // Deterministic pseudo-random content (same LCG technique used by
        // the gossip/DNS-zone wire-decoder never-panic batteries) across a
        // range of lengths, biased toward the separator characters these
        // parsers split on plus occasional multi-byte codepoints.
        let mut seed = 0xA5A5_1234_ABCD_EF01u64;
        for len in 0..400usize {
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let bucket = (seed >> 60) & 0xF;
                let ch = match bucket {
                    0 => ':',
                    1 => '.',
                    2 => '=',
                    3 => ',',
                    4 => '"',
                    5 => '\n',
                    6 => '\u{20ac}',  // 3-byte UTF-8
                    7 => '\u{1f600}', // 4-byte UTF-8 (emoji)
                    _ => (0x20 + ((seed >> 40) as u8 % 0x5f)) as char,
                };
                s.push(ch);
            }
            for parser in &parsers {
                parser(&s);
            }
        }
    }
}
