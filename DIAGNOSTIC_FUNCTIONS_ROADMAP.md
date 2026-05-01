# High-Impact Diagnostic Functions Roadmap for rustynet-sysinfo

## Overview
This document outlines 40 high-impact diagnostic functions that would significantly enhance Rustynet's visibility into system state, security posture, performance, and operational health. These functions are organized by category and prioritized by impact.

---

## 1. Network Connectivity & Topology (8 functions)

### 1.1 `active_network_routes()`
**Purpose:** Get all active routes (default gateway, specific routes)  
**Returns:** Vec<Route> with destination, gateway, metric, interface  
**Impact:** Essential for understanding network topology and detecting routing misconfigurations  
**Use Case:** Detect if default gateway is correct, verify policy-based routing

### 1.2 `mtu_path_discovery(target_host: &str)`
**Purpose:** Perform PMTUD (Path MTU Discovery) to a target  
**Returns:** DiscoveryResult { host, mtu, hops, latency }  
**Impact:** Identify MTU-related packet fragmentation issues before they cause problems  
**Use Case:** Verify MTU is optimal end-to-end through tunnel

### 1.3 `dns_resolution_latency(domain: &str, iterations: usize)`
**Purpose:** Measure DNS resolution time with min/max/avg across multiple queries  
**Returns:** DnsLatencyMetrics { min_ms, max_ms, avg_ms, stddev_ms, failures }  
**Impact:** Detect slow or flaky DNS infrastructure  
**Use Case:** Monitor DNS performance degradation before users notice

### 1.4 `bgp_route_announcements()`
**Purpose:** Check if node is announcing routes via BGP (on supported platforms)  
**Returns:** BgpStatus { enabled, announced_prefixes, peer_count }  
**Impact:** Validate exit node route advertising is working  
**Use Case:** Verify exit node properly advertises default route

### 1.5 `connection_state_histogram()`
**Purpose:** Histogram of TCP connection states (ESTABLISHED, TIME_WAIT, SYN_RECV, etc.)  
**Returns:** StateHistogram { established, time_wait, syn_recv, close_wait, ... }  
**Impact:** Detect connection leaks or state anomalies  
**Use Case:** Identify port exhaustion or connection handle leaks

### 1.6 `arp_table_entries()`
**Purpose:** List ARP cache entries with aging/staleness info  
**Returns:** Vec<ArpEntry> { ip, mac, interface, age_secs, is_permanent }  
**Impact:** Detect ARP spoofing, verify expected neighbors  
**Use Case:** Validate tunnel mesh peer connectivity via ARP

### 1.7 `listening_sockets_summary()`
**Purpose:** All listening TCP/UDP sockets with bound addresses and PID  
**Returns:** Vec<ListeningSocket> { protocol, address, port, pid, process_name }  
**Impact:** Security: detect unexpected services listening  
**Use Case:** Verify only expected Rustynet services are listening

### 1.8 `network_drop_stats()`
**Purpose:** RX/TX drops, errors, collisions per interface  
**Returns:** InterfaceDropStats { interface, rx_drops, tx_drops, rx_errors, tx_errors }  
**Impact:** Detect network instability or driver issues  
**Use Case:** Troubleshoot intermittent connectivity issues

---

## 2. Security & Cryptography (8 functions)

### 2.1 `tls_certificate_expiry_all(paths: &[&str])`
**Purpose:** Scan certificate paths, return expiry info for all certs  
**Returns:** Vec<CertExpiry> { path, subject, expires_at, days_until_expiry, is_expired }  
**Impact:** Prevent certificate-related outages  
**Use Case:** Alert on soon-to-expire certs before they break service

### 2.2 `selinux_status()`
**Purpose:** Check SELinux mode (enforcing/permissive/disabled), policy info  
**Returns:** SeLinuxStatus { enabled, mode, policy_version, violations_since_boot }  
**Impact:** Validate hardening in enforcement mode  
**Use Case:** Ensure SELinux is enforcing, not just permissive

### 2.3 `apparmor_profile_status()`
**Purpose:** List AppArmor profiles, load status for Rustynet components  
**Returns:** Vec<AppArmorProfile> { name, mode, loaded, attached_pids }  
**Impact:** Verify mandatory access control is loaded  
**Use Case:** Detect if AppArmor profiles were accidentally unloaded

### 2.4 `cryptographic_key_permissions()`
**Purpose:** Verify key file ownership, permissions, SELinux context  
**Returns:** KeyPermissionCheck { path, owner, mode, context, is_correct, issues: Vec<String> }  
**Impact:** Prevent key material exposure  
**Use Case:** Audit key custody before production deployment

### 2.5 `tls_cipher_suite_strength(host: &str, port: u16)`
**Purpose:** Connect and report negotiated cipher suite strength  
**Returns:** CipherSuiteInfo { suite_name, key_exchange, cipher, mac, tls_version, strength_bits }  
**Impact:** Detect weak cipher negotiation  
**Use Case:** Verify modern TLS versions and strong ciphers

### 2.6 `sudoers_configuration_audit()`
**Purpose:** Parse sudoers, identify privilege escalation paths  
**Returns:** SudoersAudit { total_rules, dangerous_rules: Vec<String>, nopasswd_entries }  
**Impact:** Catch overly permissive sudo rules  
**Use Case:** Security audit before giving node elevated access

### 2.7 `open_security_vulnerabilities(advisory_db_path: &str)`
**Purpose:** Check installed packages against CVE database  
**Returns:** VulnerabilityReport { vulnerable_packages: Vec<VulnPackage> { name, version, cves } }  
**Impact:** Identify exploitable software before compromise  
**Use Case:** Daily vulnerability scan in CI/CD

### 2.8 `kernel_security_parameters()`
**Purpose:** Check hardening sysctls (ASLR, kptr_restrict, dmesg_restrict, etc.)  
**Returns:** KernelSecurityParams { aslr_enabled, kptr_restrict, dmesg_restrict, panic_on_oops, ... }  
**Impact:** Verify kernel hardening in place  
**Use Case:** Ensure defense-in-depth kernel mitigations

---

## 3. System Resource Limits & Exhaustion (6 functions)

### 3.1 `file_descriptor_usage()`
**Purpose:** Current FD usage vs system limit  
**Returns:** FdUsage { used, limit, percent_used, per_process_top_10: Vec<ProcessFdUsage> }  
**Impact:** Prevent file descriptor exhaustion crashes  
**Use Case:** Alert if any process approaches FD limit

### 3.2 `memory_fragmentation_ratio()`
**Purpose:** Estimate heap fragmentation and page cache efficiency  
**Returns:** MemFragmentation { heap_fragmentation_percent, page_cache_hits_percent, swappiness }  
**Impact:** Detect memory pressure and swap thrashing  
**Use Case:** Identify need for memory tuning or instance upgrade

### 3.3 `network_socket_limit_usage()`
**Purpose:** Check ephemeral port range exhaustion and TIME_WAIT socket count  
**Returns:** SocketLimitUsage { ephemeral_range, used, available, time_wait_count, time_wait_limit }  
**Impact:** Prevent connection establishment failures under load  
**Use Case:** Tune TIME_WAIT timeout if ports are exhausting

### 3.4 `inode_usage_per_filesystem()`
**Purpose:** Inode exhaustion check per filesystem  
**Returns:** Vec<InodeUsage> { filesystem, total_inodes, used_inodes, available, percent_used }  
**Impact:** Prevent "No space left on device" during inode exhaustion  
**Use Case:** Monitor log rotation and cleanup

### 3.5 `process_thread_count_all()`
**Purpose:** Total thread count across all processes, per-process breakdown  
**Returns:** ThreadCount { total_threads, limit, percent_used, top_10_by_threads: Vec<ProcessThreads> }  
**Impact:** Detect thread leaks or exhaustion  
**Use Case:** Identify misbehaving daemon consuming all threads

### 3.6 `memory_pressure_stall_info()`
**Purpose:** PSI (Pressure Stall Information) for memory/CPU/IO  
**Returns:** PressureStallInfo { memory_some_percent_10s, cpu_some_percent_10s, io_some_percent_10s }  
**Impact:** Early warning of resource contention  
**Use Case:** Detect when system is under stress before performance collapses

---

## 4. Daemon & Service Health (6 functions)

### 4.1 `rustynetd_goroutine_count()`
**Purpose:** Count active goroutines (if exposed via metrics endpoint)  
**Returns:** GoroutineCount { count, since_startup, leaked_estimate }  
**Impact:** Detect goroutine leaks in daemon  
**Use Case:** Monitor daemon resource usage

### 4.2 `ipc_socket_responsiveness(timeout_ms: u64)`
**Purpose:** Measure IPC socket latency, test command round-trip time  
**Returns:** IpcLatency { min_ms, max_ms, avg_ms, failed_attempts, responsive: bool }  
**Impact:** Detect daemon hang or overload  
**Use Case:** Health check in automated monitoring

### 4.3 `daemon_crash_logs_recent(lines: usize)`
**Purpose:** Parse systemd journal for daemon crashes/restarts  
**Returns:** Vec<CrashLog> { timestamp, exit_code, signal, backtrace_snippet }  
**Impact:** Detect repeated crashes and identify root cause  
**Use Case:** Alert on crash loops before manual intervention needed

### 4.4 `daemon_open_file_handles()`
**Purpose:** List all files/sockets opened by daemon  
**Returns:** Vec<OpenHandle> { path, fd, type, size, inode }  
**Impact:** Detect file leaks or unexpected file access  
**Use Case:** Audit daemon file access before security review

### 4.5 `systemd_unit_dependency_graph()`
**Purpose:** Map systemd unit dependencies (wants, requires, before/after)  
**Returns:** DependencyGraph { units: Vec<UnitDeps> { name, wants, requires, blocking_units } }  
**Impact:** Understand service startup order and failure propagation  
**Use Case:** Debug startup issues when multiple services fail to start

### 4.6 `process_cpu_time_distribution()`
**Purpose:** User vs system time, check for unexpected kernel time  
**Returns:** ProcessCpuTime { user_ms, system_ms, user_percent, system_percent, children_time_ms }  
**Impact:** Detect excessive system calls or context switches  
**Use Case:** Identify inefficient code consuming kernel time

---

## 5. Storage & I/O Performance (5 functions)

### 5.1 `disk_io_latency_histogram(device: &str, duration_secs: u64)`
**Purpose:** Histogram of disk I/O latencies (read/write separately)  
**Returns:** IoLatencyHistogram { p50_ms, p95_ms, p99_ms, p999_ms, max_ms }  
**Impact:** Detect storage degradation before it impacts service  
**Use Case:** Monitor SSD wear or failing disk

### 5.2 `filesystem_journal_status()`
**Purpose:** Ext4 journal state, recovery needed, orphaned inode count  
**Returns:** JournalStatus { journal_size_mb, recovery_needed, orphaned_inodes, next_fsck_date }  
**Impact:** Predict filesystem corruption risk  
**Use Case:** Schedule maintenance before journal fills up

### 5.3 `block_device_error_counters()`
**Purpose:** SMART errors, media errors, transport errors per device  
**Returns:** Vec<DeviceErrors> { device, smart_errors, read_errors, write_errors, ata_errors }  
**Impact:** Predict disk failure before data loss  
**Use Case:** Replace disk before imminent failure

### 5.4 `directory_size_snapshot(paths: &[&str])`
**Purpose:** Recursive size of specified directories  
**Returns:** Vec<DirSize> { path, size_bytes, file_count, largest_files }  
**Impact:** Identify which directories consume disk space  
**Use Case:** Cleanup logs or temp files consuming space

### 5.5 `filesystem_cache_efficiency()`
**Purpose:** Page cache hit rate, dirty pages, writeback queue depth  
**Returns:** CacheEfficiency { cache_hit_rate_percent, dirty_pages_mb, writeback_queue_depth }  
**Impact:** Understand I/O efficiency and tune cache settings  
**Use Case:** Optimize for workload pattern

---

## 6. Compliance & Audit (4 functions)

### 6.1 `file_integrity_check(paths: &[&str])`
**Purpose:** Compare file checksums against baseline  
**Returns:** Vec<IntegrityResult> { path, matches_baseline, current_hash, baseline_hash }  
**Impact:** Detect unauthorized file modifications  
**Use Case:** Detect tampering or corruption

### 6.2 `syslog_configuration_audit()`
**Purpose:** Check syslog forwarding, log retention, permissions  
**Returns:** SyslogAudit { forwarding_enabled, destinations, log_retention_days, permissions_ok }  
**Impact:** Ensure logs are centralized and retained  
**Use Case:** Compliance audit for log retention requirements

### 6.3 `access_control_list_audit(paths: &[&str])`
**Purpose:** Report ACLs on critical files/directories  
**Returns:** Vec<AclInfo> { path, owner, group, mode, extended_acl, is_restrictive }  
**Impact:** Ensure least privilege access  
**Use Case:** Audit access before granting new permissions

### 6.4 `boot_integrity_check()`
**Purpose:** Verify secure boot status, TPM measurements, measured boot log  
**Returns:** BootIntegrity { secure_boot_enabled, tpm_present, measurements_ok, pcrs: Vec<PcrValue> }  
**Impact:** Verify boot chain integrity  
**Use Case:** Ensure hardware security features are enabled

---

## 7. System Baseline & Anomaly Detection (3 functions)

### 7.1 `system_state_snapshot()`
**Purpose:** Comprehensive snapshot of all key metrics for baseline comparison  
**Returns:** SystemSnapshot { timestamp, uptime_secs, process_count, memory_used_mb, load_avg, network_stats, disk_io }  
**Impact:** Enable comparative anomaly detection  
**Use Case:** Daily/hourly baseline to detect deviations

### 7.2 `compare_to_baseline(snapshot: &SystemSnapshot)`
**Purpose:** Compare current state to baseline, flag anomalies  
**Returns:** AnomalyReport { anomalies: Vec<Anomaly> { metric, expected, actual, deviation_percent, severity } }  
**Impact:** Automated detection of configuration drift  
**Use Case:** Alert on unexpected system behavior changes

### 7.3 `performance_regression_detection(metrics_history: &[MetricTimeseries])`
**Purpose:** Detect gradual performance degradation  
**Returns:** RegressionAnalysis { metric, trend, slope_percent_per_day, projected_failure_date }  
**Impact:** Predict when system capacity will be exceeded  
**Use Case:** Proactive capacity planning before outage

---

## Implementation Priorities

**Phase 1 (High Impact, Lower Complexity):**
- active_network_routes()
- listening_sockets_summary()
- file_descriptor_usage()
- memory_fragmentation_ratio()
- daemon_crash_logs_recent()
- ipc_socket_responsiveness()
- block_device_error_counters()
- tls_certificate_expiry_all()

**Phase 2 (High Impact, Medium Complexity):**
- connection_state_histogram()
- process_cpu_time_distribution()
- kernel_security_parameters()
- selinux_status() / apparmor_profile_status()
- filesystem_cache_efficiency()
- directory_size_snapshot()
- dns_resolution_latency()
- system_state_snapshot()

**Phase 3 (Lower Priority or Higher Complexity):**
- mtu_path_discovery()
- bgp_route_announcements()
- tls_cipher_suite_strength()
- memory_pressure_stall_info()
- disk_io_latency_histogram()
- performance_regression_detection()

---

## Cross-Platform Notes

**Linux:** Full implementation possible via /proc, /sys, systemd, audit subsystem  
**macOS:** Subset via launchd, system_statistics, process APIs; some require elevated privileges  
**Windows:** Subset via WMI, PowerShell, Event Log; Event Log parsing for crash analysis

---

## Expected Impact

- **Operational visibility:** 10x better insight into system health
- **MTTR reduction:** 50% faster root cause identification
- **Compliance:** Automated audit trail and configuration verification
- **Security:** Proactive detection of misconfigurations and vulnerabilities
- **Reliability:** Early warning system for resource exhaustion and failures
