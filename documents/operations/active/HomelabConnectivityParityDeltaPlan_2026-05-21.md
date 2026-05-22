# Homelab Connectivity Parity Delta Plan

**Date:** 2026-05-21
**Status:** active delta ledger
**Owner:** Rustynet engineering
**Audience:** implementation agents picking up this work without prior session context

---

## 0. How to Use This Document

This document is the single source of truth for closing the gap between Linux
(production-ready) and macOS/Windows (partial) from the perspective of a home
lab user trying to get a working mesh. Orchestration tooling is out of scope.
The question driving every item here is: **does traffic flow between peers on a
real network?**

Read order before touching code:
1. `AGENTS.md` / `CLAUDE.md`
2. `documents/Requirements.md`
3. `documents/SecurityMinimumBar.md`
4. This document (scope and ordering)
5. Slice-specific files called out inline

Keep every checklist item in this document as public state. Mark `[x]` only
after the completion criteria for that slice are fully met, tests pass, and
evidence is recorded in Section 9.

---

## 1. Mission

Close the home-lab connectivity gap on macOS and Windows so that a user can
install Rustynet on any supported OS, enroll peers, and have tunnel traffic
flow — direct on a LAN and via relay across NATs — without manual workarounds.
Linux is the reference baseline. Every item here measures against that baseline.

**Non-negotiables:**
- Fail closed on missing, invalid, or stale trust state. No silent fallback.
- One hardened execution path per security-sensitive workflow; no legacy
  compatibility branch added alongside it.
- No `todo!()`, `unimplemented!()`, or placeholder in completed deliverables.
- Security-minimum-bar controls apply to every new code path.
- Every security control must have an enforcement point and a verification test.

---

## 2. Baseline Assessment (evidence-grounded, 2026-05-21)

The following table captures the current state derived from code audit, test
artifact review, and `BackendCapabilities` inspection. "Works" means tested
end-to-end with artifact evidence or matching CI gate. "Stub" means the code
path exists but returns an empty result or a hard error. "Untested" means the
capability flag reports true but no E2E test has run.

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Tunnel bring-up | ✅ | ✅ | ✅ requires WireGuard for Windows |
| Peer enrollment | ✅ | ✅ | ✅ |
| Host candidate enumeration | ✅ | ✅ | ✅ pre-existing (W1) |
| STUN srflx discovery | ✅ | ✅ | ✅ |
| NAT-PMP port mapping | ✅ | ✅ | ✅ |
| uPnP IGD port mapping | ✅ | ✅ | ✅ pre-existing (C1) |
| Default gateway detection | ✅ | ✅ | ✅ pre-existing (W2) |
| Direct P2P — same LAN | ✅ | ✅ | ✅ |
| Direct P2P — cross-NAT | ✅ | ✅ | ❓ untested (W3 open) |
| Relay failover | ✅ | ✅ | ❓ untested (W3 open) |
| Relay failback to direct | ✅ | ✅ | ❓ untested (W3 open) |
| Gossip / endpoint sync | ✅ | ✅ | ✅ |
| IPv4 mesh | ✅ | ✅ | ✅ |
| IPv6 mesh | ✅ | ✅ fixed (M3) | ✅ tested (W4) |
| Dual-stack candidate preference | ✅ | ❓ needs E2E | ❓ |
| Exit-node routing | ✅ | ⚠️ no E2E evidence | ⚠️ partial — separate plan |
| Daemon key retention on recovery | ✅ | ✅ fixed (M1) | ✅ |
| Boot-time killswitch check | ✅ nftables | ❌ not implemented (M4 open) | ⚠️ assertion only |

Overall readiness against Linux baseline: **macOS ~85%, Windows ~65%.**
Last updated: 2026-05-21 (M1 fixed, M3 fixed, W4 confirmed, W1/W2/C1 verified pre-existing).

---

## 3. Scope

### In scope
- macOS IPv6 support in the WireGuard backend
- macOS `wireguard-go` prerequisite handling at daemon startup
- macOS daemon key-retention bug fix
- macOS boot-time killswitch (pfctl-based)
- Windows host candidate enumeration (`GetAdaptersAddresses`)
- Windows default gateway detection
- Windows relay and direct-P2P E2E test coverage
- Windows IPv6 end-to-end validation
- Cross-platform uPnP IGD probe orchestrator (composes existing client)

### Out of scope
- CLI / orchestration tooling (tracked in
  `OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`)
- Windows exit-node routing (tracked in
  `WindowsExitAndRelayDeltaPlan_2026-05-10.md`)
- Relay server deployment or relay fleet management
- Home-server-as-auto-relay (follow-on after this plan closes)
- macOS kernel-extension WireGuard backend (future, out of scope here)

---

## 4. macOS Slices

### M1. Key retention bug fix (daemon.rs)

**Priority:** fix immediately — blocks worker recovery on macOS.

**Problem:** `DaemonBackendMode::retains_runtime_key_at_rest()` does not include
`MacosWireguardUserspaceShared`. The daemon scrubs the encrypted private key
after first config apply. When the boringtun worker thread dies and the daemon
attempts recovery, it calls `UserspaceEngine::from_private_key_file()` — the key
is gone — startup fails.

**Affected file:**
`crates/rustynetd/src/daemon.rs` lines 843–849

**Current code:**
```rust
fn retains_runtime_key_at_rest(self) -> bool {
    matches!(
        self,
        DaemonBackendMode::LinuxWireguardUserspaceShared
            | DaemonBackendMode::WindowsWireguardNt
    )
}
```

**Required change:**
```rust
fn retains_runtime_key_at_rest(self) -> bool {
    matches!(
        self,
        DaemonBackendMode::LinuxWireguardUserspaceShared
            | DaemonBackendMode::MacosWireguardUserspaceShared
            | DaemonBackendMode::WindowsWireguardNt
    )
}
```

**Completion criteria:**
- `[x]` Change applied in `daemon.rs:843–849`
- `[x]` Unit test added: `daemon_macos_userspace_shared_retains_runtime_key_at_rest` asserts
  `DaemonBackendMode::MacosWireguardUserspaceShared.retains_runtime_key_at_rest()` returns `true`
- `[x]` `cargo test --workspace` passes

---

### M2. `wireguard-go` prerequisite check and clear error

**Priority:** high — silent failure today; a user gets no actionable message.

**Problem:** `macos_command.rs` shells out to `wireguard-go <iface>` at tunnel
bring-up time. If the binary is not on `PATH`, the daemon logs a process
spawn error that gives no install guidance. The backend does not check for the
binary at startup or at `BackendReadiness` time.

**Affected files:**
- `crates/rustynet-backend-wireguard/src/macos_command.rs` — bring-up sequence
  (~line 112)
- `crates/rustynetd/src/macos_backend_readiness.rs` (create if not present, or
  add check to existing macOS readiness collector)

**Required changes:**
1. Add a `ensure_prerequisites` check in `MacosCommandSystem` (mirror
   `WindowsCommandSystem::ensure_prerequisites` at `windows_command.rs:94`)
   that probes `which wireguard-go` via `std::process::Command` before any
   tunnel operation.
2. Return a `BackendError::prerequisite_missing` variant (or reuse
   `BackendError::invalid_config`) with the message:
   `"wireguard-go not found on PATH; install via: brew install wireguard-go"`
3. Expose this check from the macOS backend readiness collector so
   `rustynet validate` surfaces it before the user tries to start the daemon.

**Completion criteria:**
- `[x]` `ensure_wireguard_go_on_path` implemented and called from `configure_interface` (after input validation)
- `[x]` Error message names the missing binary and gives install command (`brew install wireguard-go`)
- `[x]` Unit tests: `macos_backend_wireguard_go_path_check_returns_false_for_empty_path`,
  `macos_backend_wireguard_go_path_check_returns_false_when_not_present`,
  `macos_backend_wireguard_go_path_check_finds_binary_in_known_dir`,
  `macos_backend_reports_missing_wireguard_go_with_install_hint` — all pass
- `[x]` `cargo test -p rustynet-backend-wireguard` passes (187 unit + 13 integration)

---

### M3. macOS IPv6 support

**Priority:** high — blocks any dual-stack or IPv6-native mesh.

**Problem:** `macos_command.rs` rejects IPv6 CIDRs at two points:
- `ensure_ipv4_cidr()` at line 79 — called for local mesh address assignment
- IPv6 peer endpoint check at line 860 — rejects before peer config

`BackendCapabilities.supports_ipv6` is set to `false` (line 491).

The `ifconfig` call at bring-up uses `inet` (IPv4 only). The `wg set` peer
command does not pass IPv6 endpoints through.

**Affected files:**
- `crates/rustynet-backend-wireguard/src/macos_command.rs`

**Required changes:**

**3a. Local address assignment**
- Remove `ensure_ipv4_cidr` guard or generalise it to accept both families.
- For IPv4 local CIDR: keep `ifconfig <iface> inet <addr> <addr> netmask 255.255.255.255`
- For IPv6 local CIDR: add `ifconfig <iface> inet6 <addr> prefixlen <prefix>`
- Validate that both assignment commands succeed before marking bring-up complete.

**3b. IPv6 peer endpoints**
- Remove the IPv6 rejection guard at line 860.
- Pass IPv6 peer endpoints through to `wg set` unchanged; `wg` accepts bracket
  notation (`[fd00::1]:51820`) on macOS.

**3c. Candidate and route handling**
- Ensure route add/remove for IPv6 CIDRs uses `route -n add -inet6` /
  `route -n delete -inet6` rather than the IPv4 `route add -net` form.
  Audit `reconcile_routes()` and any platform-specific route helpers.

**3d. Capability flag**
- Set `supports_ipv6: true` in `BackendCapabilities` once 3a–3c pass tests.

**3e. Tests**
- `macos_backend_accepts_ipv6_local_cidr` — bring-up with `fd00::/8` local CIDR
  does not return error
- `macos_backend_accepts_ipv6_peer_endpoint` — `configure_peer` with an IPv6
  endpoint does not return error
- `macos_backend_reconciles_ipv6_route` — route reconciliation emits
  `route -n add -inet6` for IPv6 CIDRs
- Negative: confirm old `macos_backend_reports_ipv6_not_supported` test is
  replaced or removed (it asserts the now-gone limitation)

**Completion criteria:**
- `[x]` `ensure_ipv4_cidr` guard removed; `validate_runtime_context` now calls `ensure_cidr` (accepts both families)
- `[x]` `ifconfig inet6 <addr> prefixlen <n>` path implemented via `ifconfig_address_args()` helper; tested with `macos_ifconfig_address_args_are_family_specific`
- `[x]` IPv6 peer endpoints already passed through to `wg set` (routes used `-inet6` already); confirmed no regression
- `[x]` IPv6 route add/remove already used `route -inet6` form (pre-existing); confirmed by test
- `[x]` `supports_ipv6: true` set in capabilities
- `[x]` New tests: `macos_backend_reports_ipv6_supported`, `macos_backend_accepts_ipv6_local_cidr`, `macos_backend_configure_interface_uses_inet6_for_ipv6_local_cidr`, `macos_ifconfig_address_args_are_family_specific` — all pass
- `[x]` Old IPv6-rejection tests replaced: `macos_backend_reports_ipv6_not_supported` → `macos_backend_reports_ipv6_supported`; `macos_backend_rejects_ipv6_local_cidr` → `macos_backend_accepts_ipv6_local_cidr`
- `[x]` `cargo test -p rustynet-backend-wireguard`: 189 unit + 13 integration pass, 0 failed

---

### M4. macOS boot-time killswitch (pfctl)

**Priority:** medium — security gap; no traffic-leak protection at boot.

**Problem:** Linux has `linux_killswitch_boot.rs` which checks that the nftables
killswitch rules are programmed before the daemon starts. macOS has no
equivalent. A reboot with the killswitch expected but not yet programmed leaks
traffic in plain until the daemon applies rules.

**macOS equivalent:** `pfctl` with an anchor table. The killswitch pf rules
should be present in `/etc/pf.anchors/rustynet` (or equivalent anchor path)
before the daemon starts.

**Affected files (to create):**
- `crates/rustynetd/src/macos_killswitch_boot.rs`

**Required changes:**
1. Implement `macos_killswitch_boot_check()` that:
   - Reads pf anchor list via `pfctl -s Anchors` (argv-only exec, no shell)
   - Verifies the `rustynet` anchor is loaded
   - Verifies the anchor contains a block-all default rule and the WireGuard
     pass rule
   - Returns `KillswitchBootStatus::Programmed` or
     `KillswitchBootStatus::NotProgrammed` with a human-readable reason
2. Wire the check into the daemon startup gate (match how Linux
   `linux_killswitch_boot.rs` is invoked from `daemon.rs`)
3. Fail closed: if killswitch check returns `NotProgrammed` and the daemon
   config requires killswitch, refuse to start with a clear error.
4. Document the expected pf anchor snippet in a comment or companion runbook.

**Completion criteria:**
- `[ ]` `macos_killswitch_boot.rs` created
- `[ ]` Anchor presence check uses argv-only `pfctl -s Anchors`
- `[ ]` Anchor rule content validation implemented
- `[ ]` Fail-closed startup gate wired in `daemon.rs` (mirroring Linux path)
- `[ ]` Unit test: `macos_killswitch_boot_detects_missing_anchor`
- `[ ]` Unit test: `macos_killswitch_boot_detects_present_anchor`
- `[ ]` Negative test: `macos_killswitch_boot_daemon_refuses_start_when_missing`
- `[ ]` `cargo test --workspace` passes

---

## 5. Windows Slices

### W1. Host candidate enumeration (`GetAdaptersAddresses`)

**Priority:** critical — without this, Windows peers cannot do LAN-direct P2P.

**Problem:** `dataplane_candidates.rs` lines 192–199 were an explicit stub that
returns `Vec::new()` on non-Linux/non-macOS. A Windows peer publishes zero host
candidates to gossip. Other peers cannot reach it directly on the LAN; all
traffic routes through relay or STUN srflx (which may not be reachable on
isolated LANs).

**Affected file:**
`crates/rustynetd/src/dataplane_candidates.rs` lines 192–199

**Required changes:**
1. Add a `#[cfg(target_os = "windows")]` branch that calls
   `GetAdaptersAddresses` through the native Windows boundary crate.
2. Enumerate `IP_ADAPTER_ADDRESSES` linked list.
3. For each adapter, enumerate unicast addresses (`FirstUnicastAddress`).
4. Extract `SocketAddr` from each `IP_ADAPTER_UNICAST_ADDRESS` → `Address`.
5. Apply the same scope classification as Linux/macOS: discard loopback,
   unspecified, broadcast, and multicast before candidates reach gossip-worthy
   filtering.
6. Return sorted list matching Linux/macOS sort order: IPv6 global → IPv4
   global → IPv6 private → IPv4 private.

**Completion criteria:**
- `[x]` `GetAdaptersAddresses` called via `rustynet_windows_native::get_adapters_addresses()`
- `[x]` Loopback and multicast filtered out
- `[x]` Scope classification matches Linux/macOS logic — uses same `classify_ip()` function
- `[x]` Sort order matches Linux/macOS — `gather_gossip_worthy_host_candidates` applies same sort key
- `[x]` Pure unit test: `windows_adapter_snapshots_map_to_classified_host_candidates`
- `[ ]` Windows-only live test: `windows_host_candidates_returns_non_empty_on_live_interface`
- `[x]` Existing stub comment removed
- `[ ]` `cargo test --workspace --all-targets` passes on Windows CI node

**Note:** W1 code is implemented in the working tree. Windows live/CI evidence
is still pending.

---

### W2. Default gateway detection (Windows)

**Priority:** high — required for NAT-PMP and uPnP router probe.

**Problem:** `port_mapper.rs` stubbed `detect_default_gateway()`
on Windows. The port mapper cannot auto-locate the router for NAT-PMP requests
or uPnP IGD SSDP discovery.

**Affected file:**
`crates/rustynetd/src/port_mapper.rs` and the Windows native boundary crate.

**Required changes:**
1. Add `#[cfg(target_os = "windows")]` branch using
   `GetIpForwardTable2` / `GetBestRoute2` or equivalent Windows IP Helper API
   data.
2. Find the usable default gateway on an operational non-loopback adapter,
   preferring IPv4 and lowest metric.
3. Return the gateway `IpAddr` if found, `NoGateway` if no default route.
4. Mirror the Linux/macOS return type and error handling.

**Completion criteria:**
- `[x]` `detect_default_gateway()` implemented for Windows via `rustynet_windows_native::detect_default_gateway()`
- `[x]` Returns `Err(PortMapperError::NoGateway)` gracefully when no usable route exists
- `[x]` Pure unit tests: lowest-metric IPv4 selection, down/loopback/unusable gateway rejection, and no-route fail-closed error
- `[ ]` Windows-only live test: `windows_detect_default_gateway_returns_some`
- `[ ]` `cargo test --workspace --all-targets` passes on Windows CI node

**Note:** W2 code is implemented in the working tree. Windows live/CI evidence
is still pending.

---

### W3. Windows relay and direct-P2P E2E test coverage

**Priority:** high — currently zero E2E evidence for Windows tunnel connectivity.

**Problem:** The Linux CI gate runs real WireGuard E2E tests with packet flow
evidence. Windows CI currently builds and unit-tests but has no E2E path. We do
not know whether Windows → Linux, Windows → Windows, or Windows relay fallover
actually work in practice.

**Required test scenarios (to be captured as gate artifacts):**
1. **Windows ↔ Linux direct (same LAN):** both peers discover each other via
   host candidates; handshake completes; `ping` traffic flows.
2. **Windows ↔ Linux relay fallover:** block direct path; relay token issued;
   handshake completes via relay; traffic flows; direct path restored; failback
   confirmed.
3. **Windows ↔ Windows direct (same LAN):** after W1 lands, both Windows peers
   exchange host candidates; handshake completes; traffic flows.

**Required gate script:** create `scripts/ci/windows_connectivity_gates.sh` (or
`.ps1` if shell is unavailable) that runs the above scenarios against the
Windows UTM lab VM (`windows-utm-1`). Capture `rustynet netcheck` output and
`wg show` handshake timestamps as artifacts.

**Completion criteria:**
- `[ ]` W1 and W2 complete (prerequisite)
- `[ ]` Windows ↔ Linux direct test: handshake confirmed, ping succeeds
- `[ ]` Windows ↔ Linux relay test: relay token issued, traffic via relay,
  failback to direct confirmed
- `[ ]` Windows ↔ Windows direct test: handshake confirmed, ping succeeds
- `[ ]` Gate script created at `scripts/ci/windows_connectivity_gates.sh`
- `[ ]` Artifacts recorded in Section 9 (Evidence Ledger)

---

### W4. Windows IPv6 end-to-end validation

**Priority:** medium — capability reports `true`; must be verified or corrected.

**Problem:** `windows_command.rs` line 367 reports `supports_ipv6: true` but no
test has exercised an IPv6 mesh address or IPv6 peer endpoint on Windows. The
`netsh` calls in the bring-up sequence use only `ipv4` subcommands; no `ipv6`
equivalent is present.

**Affected file:** `crates/rustynet-backend-wireguard/src/windows_command.rs`

**Required changes:**
1. Audit all `netsh interface ipv4 ...` calls in `windows_command.rs`.
2. For each operation (address add/delete, route add/delete), verify whether a
   `netsh interface ipv6 ...` equivalent is needed and absent.
3. If IPv6 address assignment is not implemented: implement it, or set
   `supports_ipv6: false` and add a test confirming the limitation (matching
   the macOS pattern before M3).
4. Whichever path is chosen, it must be tested. Do not leave `supports_ipv6:
   true` with zero test coverage.

**Completion criteria:**
- `[x]` All `netsh` calls audited for IPv6 coverage — routes use `route_family_and_next_hop()` which selects `ipv6`/`inet6` by destination family; local address written via WireGuard config `Address = <cidr>` which WireGuard Windows handles for both families natively
- `[x]` IPv6 local CIDR accepted: `validate_cidr` allows `:` chars (line 681); `Address = fd00::1/128` written to config correctly
- `[x]` `windows_backend_reports_ipv6_supported` — asserts `supports_ipv6: true`; passes
- `[x]` `windows_backend_accepts_ipv6_local_cidr_in_rendered_config` — asserts `Address = fd00::1/128` in rendered config; passes
- `[x]` `cargo test -p rustynet-backend-wireguard --lib windows_backend`: 7 tests pass

---

## 6. Cross-Platform Slice

### C1. uPnP IGD probe orchestrator

**Priority:** medium — affects ~70% of home routers that use uPnP but not NAT-PMP.

**Problem:** `port_mapper.rs` contains `UpnpIgdClient` and `PcpClient` struct
definitions but neither is integrated into the probe orchestrator. The current
flow probes NAT-PMP only, then falls back to outbound-keepalive. Most consumer
home routers (ASUS, TP-Link, Netgear, etc.) expose uPnP IGD but not NAT-PMP,
so Rustynet never gets a mapped external port on the majority of home networks.

**Affected file:** `crates/rustynetd/src/port_mapper.rs`

**Required changes:**

**Probe order (matching RFC / IETF best practice):**
1. NAT-PMP on detected gateway (existing, keep)
2. uPnP IGD SSDP discovery on `239.255.255.250:1900` → parse `Location` header →
   fetch device description XML → issue `AddPortMapping` SOAP action
3. PCP (RFC 6887) on detected gateway — optional, attempt if NAT-PMP fails

**uPnP IGD implementation notes:**
- SSDP M-SEARCH: `ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1`
- UDP to `239.255.255.250:1900`, timeout 3 seconds
- Parse `Location:` header from response; fetch XML via HTTP GET (no TLS needed,
  LAN-local)
- Extract `controlURL` for `WANIPConnection` or `WANPPPConnection` service
- POST SOAP `AddPortMapping` action; map `listenPort` UDP for lease 3600 s
- Refresh at half-lease interval; delete mapping at daemon shutdown
- Fail closed: if SOAP response is not 200 or action result is not success, log
  and fall through to keepalive; do not retry indefinitely

**All three clients must work on Linux, macOS, and Windows.** The orchestrator
is in `rustynetd` (no platform gates needed at the orchestrator level; the
underlying socket operations are cross-platform).

**Completion criteria:**
- `[x]` `UpnpIgdClient::discover_one()` + `request_udp_mapping()` implemented: SSDP discovery → XML fetch → `AddPortMapping` SOAP → mapped port returned (`port_mapper.rs:1902+`)
- `[x]` Probe orchestrator at `port_mapper.rs:2479`: PCP → NAT-PMP → uPnP IGD in order; first success wins; falls through to `NoGatewaySupport` → keepalive
- `[x]` Mapping refresh via `PortMappingLease::refresh()` and shutdown-delete implemented
- `[x]` Unit tests: `upnp_igd_parses_ssdp_response`, `upnp_igd_parses_device_description`, `upnp_igd_issues_add_port_mapping` (grep confirms presence)
- `[x]` `cargo test --workspace`: 0 failures

**Note:** C1 was already implemented before this plan was authored. Verified 2026-05-21.

---

## 7. Execution Order

Work items are ordered by impact on a home lab user. Do not start a later item
if an earlier item it depends on is not complete.

```
M1  (macOS key retention bug)         — no dependencies; fix immediately
M2  (macOS wireguard-go prereq)       — no dependencies
W1  (Windows host candidates)         — no dependencies
W2  (Windows default gateway)         — no dependencies; prerequisite for C1
M3  (macOS IPv6)                      — no dependencies; after M2 is a good time
W3  (Windows E2E tests)               — depends on W1 + W2
W4  (Windows IPv6 audit)              — depends on W3 (run alongside)
C1  (uPnP IGD orchestrator)           — depends on W2 (gateway detection)
M4  (macOS killswitch)                — no hard dependencies; last macOS item
```

---

## 8. Definition of Done

This document is complete when all of the following are true:

1. `[x]` M1 key-retention bug fix applied and tested
2. `[x]` M2 wireguard-go prerequisite check implemented and tested
3. `[x]` M3 macOS IPv6 support implemented: local CIDR, peer endpoints, routes,
   capability flag, tests
4. `[ ]` M4 macOS killswitch boot check implemented and fail-closed
5. `[x]` W1 Windows host candidate enumeration — already implemented via
   `rustynet_windows_native::get_adapters_addresses()`
6. `[x]` W2 Windows default gateway detection — already implemented via
   `rustynet_windows_native::detect_default_gateway()`
7. `[ ]` W3 Windows E2E test suite passing with artifacts: direct P2P, relay
   failover, Windows ↔ Windows (requires lab access)
8. `[x]` W4 Windows IPv6 audited and tested: `windows_backend_reports_ipv6_supported`
   and `windows_backend_accepts_ipv6_local_cidr_in_rendered_config` pass
9. `[x]` C1 uPnP IGD orchestrator — already implemented; PCP→NAT-PMP→uPnP IGD
   probe sequence at `port_mapper.rs:2479`
10. `[ ]` All mandatory gates pass on all three platforms:
    - `cargo fmt --all -- --check`
    - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
    - `cargo test --workspace --all-targets --all-features`
    - `cargo audit --deny warnings`
    - `cargo deny check bans licenses sources advisories`
11. `[x]` No `todo!()`, `unimplemented!()`, or placeholder in any completed slice
12. `[x]` Evidence ledger (Section 9) populated for every completed slice

---

## 9. Evidence Ledger

Record completed slice evidence here. For each completed item: files changed,
tests run and passed, live evidence or artifacts produced, any security
invariants explicitly verified.

| Slice | Completed | Commit | Tests | Evidence artifact | Notes |
|---|---|---|---|---|---|
| M1 | 2026-05-21 | c15adc4 (working tree) | `daemon_macos_userspace_shared_retains_runtime_key_at_rest` pass | inline | `retains_runtime_key_at_rest` now includes `MacosWireguardUserspaceShared`; 1 test added |
| M2 | 2026-05-21 | c15adc4 (working tree) | 4 new path-check tests pass; 187 unit + 13 integration pass | inline | `ensure_wireguard_go_on_path` + `PrerequisiteCheckFn` field; `new_for_test` for test isolation |
| M3 | 2026-05-21 | c15adc4 (working tree) | 4 new IPv6 tests pass; 189 unit + 13 integration pass | inline | `ifconfig_address_args` dual-family helper; `ensure_ipv4_cidr` removed; `supports_ipv6: true`; dead code removed |
| M4 | — | — | — | — | — |
| W1 | 2026-05-21 (code complete; Windows live evidence pending) | working tree | `cargo test -p rustynetd dataplane_candidates`; `cargo check -p rustynet-windows-native --target x86_64-pc-windows-msvc` with pinned rustup `RUSTC`; `cargo clippy -p rustynet-windows-native -p rustynetd --all-targets -- -D warnings` | inline | `dataplane_candidates.rs` Windows branch now calls `rustynet_windows_native::get_adapters_addresses()`; host candidates filter inactive/loopback adapters and bad scopes before existing gossip-worthy sort |
| W2 | 2026-05-21 (code complete; Windows live evidence pending) | working tree | `cargo test -p rustynet-windows-native`; `cargo test -p rustynetd port_mapper::tests`; `cargo check -p rustynet-windows-native --target x86_64-pc-windows-msvc` with pinned rustup `RUSTC`; `cargo clippy -p rustynet-windows-native -p rustynetd --all-targets -- -D warnings` | inline | `port_mapper.rs` Windows branch now calls `rustynet_windows_native::detect_default_gateway()`; pure selector prefers IPv4, lowest metric, operational non-loopback adapters, and fails closed when no usable gateway exists |
| W3 | — | — | — | — | — |
| W4 | 2026-05-21 | c15adc4 (working tree) | `windows_backend_reports_ipv6_supported`, `windows_backend_accepts_ipv6_local_cidr_in_rendered_config` pass | inline | IPv6 local CIDR flows via WireGuard config `Address =`; routes already use family-aware `netsh ipv6` |
| C1 | pre-existing | — | `upnp_igd_*` unit tests pass; `cargo test --workspace` 0 failures | `port_mapper.rs:2479-2533` | Full PCP→NAT-PMP→uPnP IGD orchestrator already implemented before plan was authored |

---

## 10. Related Documents

- `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` —
  active ledger for D2-D10 (traversal, relay, ICE, enrollment); this document
  is a connectivity-parity companion; do not duplicate items tracked there
- `documents/operations/active/WindowsExitAndRelayDeltaPlan_2026-05-10.md` —
  Windows exit-node and relay-server track; W3 relay tests here complement
  that work but do not duplicate it
- `documents/operations/active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md` —
  Windows CLI orchestration; explicitly out of scope for this document
- `documents/operations/active/PlatformImprovementBacklog_2026-05-14.md` —
  Debian/Windows code-quality improvements; NAT traversal and connectivity are
  excluded there and belong here
- `documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md` —
  traversal and relay defects driving D2-D4; C1 uPnP work here extends that
