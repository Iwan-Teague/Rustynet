# Rustynet CLI Commands — Design and Implementation Guide

## Overview

This document outlines CLI commands for Rustynet, split into two sections:
1. **Completed (Phases 1-3)**: 21 commands fully implemented, tested, and deployed
2. **Proposed Future (Phases 4+)**: New useful commands for node management, policy, analytics, and advanced diagnostics

All commands pull real live data via the `rustynet-sysinfo` crate and return actionable operational info.

---

## Architecture and Implementation Location

### Primary Location: `rustynet-cli`

**File**: `crates/rustynet-cli/src/main.rs`

- Add command variants to the `CliCommand` enum
- Add parsing logic to the `parse_command()` function
- Wire new commands into the main match statement

### Data Collection: `rustynet-sysinfo`

**File**: `crates/rustynet-sysinfo/src/lib.rs`

- Already contains 60+ system-info functions (network, CPU, disk, memory, routes, DNS, etc.)
- Functions abstract OS differences via internal `_internal()` implementations
- Each platform (macOS, Linux, Windows) has platform-specific code that returns real data

### Output Format

- Default: human-readable table/list format
- Add `--json` flag to all new commands for machine-readable output
- Timestamps in ISO 8601 format
- Numeric units consistent (bytes, ms, %)

---

## Cross-Platform Requirements

**All commands must work on:**
- macOS (Intel + Apple Silicon)
- Windows 10+
- Debian 11+

**Implementation strategy:**
- Leverage existing `cfg(target_os = "...")` patterns in `rustynet-sysinfo`
- Use platform-agnostic system calls where possible (procfs, WMI, sysctl, etc.)
- No stubs or placeholders; return real data from live OS interfaces
- Use existing helpers for process control, route enumeration, network stats

---

## Completed Commands (Phases 1-3) ✓

All commands below are fully implemented, tested, and production-ready.

### Category 1: Network Diagnostics ✓

#### 1.1 `rustynet network latency [--target <host>] [--count <n>] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Measure latency to peer nodes or external hosts.

**Output Fields:**
- Target hostname/IP
- Min/max/avg/stddev latency (ms)
- Packet loss (%)

#### 1.2 `rustynet network routes [--verbose] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Show all active routes in routing table, including tunnel-specific ones.

**Output Fields:**
- Destination CIDR
- Gateway IP
- Interface
- Metric

#### 1.3 `rustynet network interfaces [--stats] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: List active network interfaces with live stats.

**Output Fields:**
- Interface name
- IP address(es)
- MAC address, MTU, status
- RX/TX bytes/errors (with `--stats`)

#### 1.4 `rustynet network dns [--test <domain>] [--resolver] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Show DNS configuration and test resolution quality.

**Output Fields:**
- Configured resolver(s)
- Response time (ms)
- Success rate (%)

---

### Category 2: Tunnel and Peer Status ✓

#### 2.1 `rustynet tunnel status [--detailed] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Show tunnel interface status and peer summary.

**Output Fields:**
- Interface status (up/down)
- Local address, bytes sent/received
- Last handshake timestamp
- Peer count

#### 2.2 `rustynet peers [--latency] [--extended] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: List WireGuard peers with optional metrics.

**Output Fields:**
- Peer name, tunnel IP
- Last seen, latency (with flags)
- Endpoint info (with --extended)

---

### Category 3: System Health and Resources ✓

#### 3.1 `rustynet system health [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Snapshot of system health (CPU, memory, disk, uptime).

**Output Fields:**
- CPU cores, memory %, disk %, load average
- Uptime, rustynetd process status

#### 3.2 `rustynet system load [--history <interval>] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Real-time load monitoring with optional history sampling.

**Output Fields:**
- Timestamp, CPU%, memory%, load (1m/5m/15m)

#### 3.3 `rustynet system disk [--detailed] [--io-stats] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Disk usage and I/O statistics.

**Output Fields:**
- Mount point, total/used/available GB, usage %
- I/O operations, latency (with --io-stats)

---

### Category 4: Security and Validation ✓

#### 4.1 `rustynet security check [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Validate security properties (permissions, TLS certs, config integrity).

**Output Fields:**
- Check name, status (PASS/FAIL/WARN)
- Details (permissions, cert validity, etc.)

#### 4.2 `rustynet security audit [--remediate] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Audit environment variables and config for leaks/misconfigurations.

**Output Fields:**
- Audit item, status, detail
- Optional remediation suggestions (with --remediate)

---

### Category 5: Troubleshooting and Diagnostics ✓

#### 5.1 `rustynet debug packet [--count <n>] [--interface <iface>] [--verbose] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Capture and display live network packets on specified interface.

**Output Fields:**
- Timestamp, protocol, source/dest, packet size
- Full header details (with --verbose)

#### 5.2 `rustynet debug connections [--filter <pattern>] [--sort <field>] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: List TCP/UDP connections with optional filtering and sorting.

**Output Fields:**
- Local address/port, remote address/port, state
- Process info, optional filtering by pattern

#### 5.3 `rustynet debug trace-route <destination> [--hops <max>] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Show network path to destination (cross-platform).

**Output Fields:**
- Hop number, IP/hostname, latency (ms)
- TTL exceeded or destination reached indicators

#### 5.4 `rustynet debug arp [--watch] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Display ARP table entries.

**Output Fields:**
- IP address, MAC address, interface
- Age (secs), permanent flag

---

### Category 6: Performance and Benchmarking ✓

#### 6.1 `rustynet perf bandwidth [--duration <secs>] [--target <host>] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Measure bandwidth to peer or external target.

**Output Fields:**
- Download/upload Mbps
- Latency (ms)

#### 6.2 `rustynet perf socket-stats [--detailed] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Show socket statistics and buffer usage.

**Output Fields:**
- Established, listening, time-wait counts
- Total socket count

#### 6.3 `rustynet perf cpu-profile [--duration <secs>] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Profile CPU usage of rustynetd process.

**Output Fields:**
- PID, CPU %, memory (MB)

---

### Category 7: Logging and Observability ✓

#### 7.1 `rustynet logs tail [--lines <n>] [--follow] [--filter <pattern>] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Tail recent logs with optional filtering and follow mode.

**Output Fields:**
- Timestamp, log level, source, message
- Filtered by regex pattern (with --filter)

#### 7.2 `rustynet logs errors [--since <duration>] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Aggregate and display recent errors with deduplication.

**Output Fields:**
- Error type, count, last seen timestamp
- Message, stack trace snippet

#### 7.3 `rustynet logs export [--format <json|csv>] [--since <duration>] [--to-file <path>] [--json]` ✓

**Status**: Implemented and verified

**Purpose**: Export logs in structured format for analysis.

**Output Fields:**
- Timestamp, level, source, message (all fields)
- Supports JSONL and CSV output formats

---

## Proposed Future Commands (Phases 4+)

These are useful additions for advanced node management, policy control, and analytics.

### Category 8: Node and Membership Management

#### 8.1 `rustynet node info [--peers] [--json]`

**Purpose**: Display information about this node in the mesh.

**Output Fields:**
- Node ID, public key, role (relay/exit/standard)
- Join date, last heartbeat
- Peer count (with --peers)
- Trust state freshness

**Implementation:**
- Data source: membership state, node metadata
- Parse node ID from config or daemon state

#### 8.2 `rustynet node list [--role <relay|exit|all>] [--filter <status>] [--json]`

**Purpose**: List all known nodes in the mesh with optional filtering.

**Output Fields:**
- Node ID, role, IP address, endpoint (if known)
- Last seen timestamp, latency (if measured)
- Status (online/offline/unknown)

**Implementation:**
- Data source: membership snapshot + peer store
- Poll daemon for live peer status

#### 8.3 `rustynet node probe <node-id> [--tcp-port <port>] [--udp-port <port>] [--json]`

**Purpose**: Probe reachability to a specific node across different transports.

**Output Fields:**
- Node ID, target transport
- Reachable (true/false), latency (ms)
- Endpoint discovered (direct IP + port)

**Implementation:**
- Data source: custom probe logic (ICMP, TCP SYN, UDP echo)
- Try multiple transports; report first successful

---

### Category 9: Policy and Authorization

#### 9.1 `rustynet policy list [--node <id>] [--json]`

**Purpose**: Display active policies and allow rules.

**Output Fields:**
- Policy name, direction (inbound/outbound)
- Source/destination (node ID or CIDR)
- Protocol, port range, action (allow/deny)

**Implementation:**
- Data source: policy-engine state from daemon
- Parse PolicySet and PolicyRule from control plane

#### 9.2 `rustynet policy apply <policy-file> [--dry-run] [--json]`

**Purpose**: Apply or preview new policy configuration.

**Output Fields:**
- Changes detected (added/modified/removed rules)
- Affected peers/nodes
- Validation results (with --dry-run)

**Implementation:**
- Data source: policy-file + current state comparison
- Validate syntax and rule overlap

#### 9.3 `rustynet policy test <source-node> <dest-node> [--protocol tcp|udp] [--port <n>] [--json]`

**Purpose**: Test whether a specific flow is allowed by current policy.

**Output Fields:**
- Source, destination, protocol, port
- Allowed (true/false), matching rule
- Reason if denied

**Implementation:**
- Simulate policy evaluation logic
- Return first matching rule

---

### Category 10: Relay and Exit Node Management

#### 10.1 `rustynet relay list [--status] [--json]`

**Purpose**: List configured relay servers and their status.

**Output Fields:**
- Relay ID/hostname, role (relay/exit)
- Load (active connections), uptime
- Geographic location (if known)

**Implementation:**
- Data source: relay store + endpoint hints
- Poll relay health checks

#### 10.2 `rustynet relay select [--best-latency] [--least-load] [--json]`

**Purpose**: Query or override relay selection strategy.

**Output Fields:**
- Current relay, reason (manual/auto/latency/load)
- Alternative relays ranked by metric
- Override hint (if set)

**Implementation:**
- Data source: endpoint-hint bundle + live latency
- Show ranking and selection criteria

#### 10.3 `rustynet relay health <relay-id> [--json]`

**Purpose**: Detailed health check of specific relay.

**Output Fields:**
- Relay ID, status (healthy/degraded/down)
- RTT (ms), packet loss (%)
- Last probe timestamp, consecutive failures

**Implementation:**
- Data source: live probe or cached health stats
- Show historical availability trend (uptime %)

---

### Category 11: Certificate and Trust Management

#### 11.1 `rustynet cert list [--expired] [--expiring-soon] [--json]`

**Purpose**: List all certificates (node, TLS, trust anchors) with expiry info.

**Output Fields:**
- Certificate subject, issuer, serial
- Issued date, expires date, days remaining
- Type (node/TLS/trust-anchor), key size

**Implementation:**
- Data source: config PKI + systemd certs
- Scan cert directories, parse PEM/DER

#### 11.2 `rustynet cert check [--strict] [--json]`

**Purpose**: Comprehensive certificate validation and chain verification.

**Output Fields:**
- Certificate status (valid/expired/revoked/invalid-chain)
- Chain depth, root trust
- Warnings (weak key, future date, etc.)

**Implementation:**
- Data source: cert validation logic from crypto crate
- Verify signatures, check revocation (if CRL available)

#### 11.3 `rustynet trust-state show [--anchor <node-id>] [--json]`

**Purpose**: Display current trust state (signed state artifact) and verification.

**Output Fields:**
- Trust state version, timestamp, signer
- State freshness (current/stale), age (seconds)
- Member list (count), policy version

**Implementation:**
- Data source: signed trust-state artifact from daemon
- Show parse result and signature validation

---

### Category 12: Analytics and Metrics

#### 12.1 `rustynet analytics peers [--window <duration>] [--sort <metric>] [--json]`

**Purpose**: Peer health trends and latency heatmap.

**Output Fields:**
- Peer ID, avg latency (ms), min/max, stddev
- Uptime (%), data transferred (GB)
- Availability over time window (sparkline)

**Implementation:**
- Data source: historical metrics (if stored; otherwise recent samples)
- Collect samples, compute percentiles and trends

#### 12.2 `rustynet analytics traffic [--interval <duration>] [--top <n>] [--json]`

**Purpose**: Traffic summary by peer, node, or protocol.

**Output Fields:**
- Source→destination, protocol, port
- Bytes sent/received, packet count, duration
- Average throughput (Mbps)

**Implementation:**
- Data source: netlink or packet-level analytics
- Aggregate by 5-min intervals, report top-N

#### 12.3 `rustynet analytics latency-heatmap [--peers] [--relays] [--json]`

**Purpose**: Latency matrix between this node and all peers/relays.

**Output Fields:**
- Matrix: rows = destinations, cols = latency percentile (p50/p95/p99)
- Color-coded output (human-readable) or JSON

**Implementation:**
- Data source: ongoing latency probes
- Generate heatmap ASCII or JSON grid

---

### Category 13: Backup and Recovery

#### 13.1 `rustynet backup state [--path <dir>] [--compress] [--encrypt] [--json]`

**Purpose**: Snapshot and backup node state (keys, config, certs, trust state).

**Output Fields:**
- Backup location, size (bytes)
- Items included (keys, config, certs, metadata)
- Encryption status, timestamp

**Implementation:**
- Data source: config dirs + daemon state export
- Tar/gzip and optionally encrypt with node key

#### 13.2 `rustynet restore state [--path <backup-file>] [--verify] [--dry-run] [--json]`

**Purpose**: Restore node state from backup.

**Output Fields:**
- Restore location, items restored
- Verification result (checksums match)
- Conflicts (if any files already exist)

**Implementation:**
- Data source: backup tarball
- Unpack, verify signatures, prompt on conflicts

#### 13.3 `rustynet export-keys [--format <pem|raw>] [--path <file>] [--json]`

**Purpose**: Export node private keys for offline storage (with warnings).

**Output Fields:**
- Key material exported (confirm path)
- Format used, file permissions recommended
- DANGER warning: ensure secure storage

**Implementation:**
- Data source: encrypted key storage
- Prompt for passphrase, export unencrypted or re-encrypt

---

### Category 14: Configuration Management

#### 14.1 `rustynet config show [--section <name>] [--json]`

**Purpose**: Display current configuration with safe defaults visible.

**Output Fields:**
- Config section, keys and values
- Defaults vs. overrides highlighted
- Sensitive fields (redacted)

**Implementation:**
- Data source: daemon config struct or config file
- Pretty-print with comments

#### 14.2 `rustynet config validate [--strict] [--json]`

**Purpose**: Validate configuration syntax and semantic constraints.

**Output Fields:**
- Valid (true/false), errors/warnings
- Constraint violations (e.g., port range, CIDR overlap)
- Suggestions for fixes

**Implementation:**
- Data source: config parser + validator
- Check required fields, type correctness, range constraints

#### 14.3 `rustynet config export [--format <toml|json|yaml>] [--path <file>] [--json]`

**Purpose**: Export current configuration in portable format.

**Output Fields:**
- Export format, file path, size
- All sections included, sensitive fields redacted

**Implementation:**
- Data source: daemon config state
- Serialize to requested format

---

## Summary Table — Completed Commands ✓

| Command | Category | Status | Tests | Cross-Platform |
|---------|----------|--------|-------|-----------------|
| `network latency` | Diagnostics | ✓ Complete | ✓ Pass | ✓ |
| `network routes` | Diagnostics | ✓ Complete | ✓ Pass | ✓ |
| `network interfaces` | Diagnostics | ✓ Complete | ✓ Pass | ✓ |
| `network dns` | Diagnostics | ✓ Complete | ✓ Pass | ✓ |
| `tunnel status` | Tunnel/Peer | ✓ Complete | ✓ Pass | ✓ |
| `peers` | Tunnel/Peer | ✓ Complete | ✓ Pass | ✓ |
| `system health` | Health | ✓ Complete | ✓ Pass | ✓ |
| `system load` | Health | ✓ Complete | ✓ Pass | ✓ |
| `system disk` | Health | ✓ Complete | ✓ Pass | ✓ |
| `security check` | Security | ✓ Complete | ✓ Pass | ✓ |
| `security audit` | Security | ✓ Complete | ✓ Pass | ✓ |
| `debug packet` | Troubleshoot | ✓ Complete | ✓ Pass | ✓ |
| `debug connections` | Troubleshoot | ✓ Complete | ✓ Pass | ✓ |
| `debug trace-route` | Troubleshoot | ✓ Complete | ✓ Pass | ✓ |
| `debug arp` | Troubleshoot | ✓ Complete | ✓ Pass | ✓ |
| `perf bandwidth` | Perf | ✓ Complete | ✓ Pass | ✓ |
| `perf socket-stats` | Perf | ✓ Complete | ✓ Pass | ✓ |
| `perf cpu-profile` | Perf | ✓ Complete | ✓ Pass | ✓ |
| `logs tail` | Logging | ✓ Complete | ✓ Pass | ✓ |
| `logs errors` | Logging | ✓ Complete | ✓ Pass | ✓ |
| `logs export` | Logging | ✓ Complete | ✓ Pass | ✓ |

---

## Implementation Priority — Future Phases

**Phase 4 (High Value)**: Node and membership insights
- `node info`, `node list`, `node probe`
- Enables faster peer discovery and network topology visualization

**Phase 5 (Policy & Security)**:
- `policy list`, `policy test`, `policy apply`
- `cert list`, `trust-state show`
- Critical for multitenancy and compliance

**Phase 6 (Operations & Observability)**:
- `relay list`, `relay health`, `relay select`
- `analytics peers`, `analytics traffic`
- Improves operational visibility

**Phase 7+ (Advanced)**:
- `backup state`, `restore state`, `export-keys`
- `config export`, `config validate`
- `analytics latency-heatmap`
- Nice-to-have but lower priority

---

## Acceptance Criteria

For each implemented command:

1. **Real Data**: Returns live OS-level data, never stubs or placeholders
2. **Cross-Platform**: Executes correctly on macOS, Windows, Debian without runtime failures
3. **No Placeholders**: All functions wired; no TODO/FIXME in production paths
4. **Error Handling**: Graceful fallback if permission denied or data unavailable
5. **Output Format**: Default human-readable, `--json` option for all commands
6. **Unit Tests**: Tests validate data types and output format
7. **Documentation**: Command help text (`--help`) explains purpose and output fields

---

## Notes

- Completed 21 commands (Phases 1-3) cover core diagnostics, troubleshooting, and performance profiling
- Future commands (Phases 4+) focus on node management, policy, and analytics—higher-level operations
- Prioritize Phase 4-5 commands for enterprise use cases (multitenancy, compliance, auditing)
- All commands should emit structured JSON for automation and monitoring integrations
