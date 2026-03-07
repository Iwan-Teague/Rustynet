# Comparative Security Flaw Assessment (2026-03-06)

## Scope
- Repository: Rustynet (point-in-time review on 2026-03-06)
- Method:
  - static review of security-sensitive code paths and scripts,
  - comparison against real incidents in similar VPN/network-overlay projects.
- Goal:
  - identify potential flaws (not only confirmed exploits),
  - map external incident lessons to concrete Rustynet hardening actions.

Severity scale used:
- `Critical`: can directly enable bypass of trust or tunnel guarantees.
- `High`: materially weakens privileged boundaries or release assurance.
- `Medium`: plausible abuse path, requires chaining or specific conditions.
- `Low`: hardening debt that expands attack surface or future regressions.

## 1) Rustynet Potential Flaw Register

### F-01: Break-glass manual peer programming can bypass signed control workflows
- Severity: `High`
- Evidence:
  - `start.sh:3348`
  - `start.sh:3350`
  - `start.sh:3351`
  - `start.sh:3406`
  - `start.sh:3471`
- Why this matters:
  - Direct `wg set` + `ip route` mutation from interactive shell bypasses centrally signed assignment flow.
  - Compromised admin account or social engineering of an operator can create unauthorized peer/route state.
- Recommended hardening:
  - Remove shell-level manual peer mutation paths and enforce signed assignment workflows as the only mutation path.
  - If a future emergency path is reintroduced, require a signed, short-lived break-glass token and typed validation.
  - Keep explicit audit trail, but make it structured and tamper-evident (signed append records).
- Status: `Mitigated on 2026-03-06 (manual shell mutation path removed)`

### F-02: Peer store input and file-custody controls are weaker than other sensitive state
- Severity: `Medium`
- Evidence:
  - `start.sh:2816`
  - `start.sh:2827`
  - `start.sh:2894`
  - `start.sh:2933`
  - `start.sh:3808`
  - `crates/rustynet-cli/src/main.rs:486`
  - `crates/rustynet-cli/src/main.rs:490`
  - `crates/rustynet-cli/src/ops_peer_store.rs:17`
  - `crates/rustynet-cli/src/ops_peer_store.rs:30`
  - `crates/rustynet-cli/src/ops_peer_store.rs:82`
  - `crates/rustynet-cli/src/ops_peer_store.rs:246`
- Why this matters:
  - Prior implementation relied on shell-managed peer-store validation/read paths, which are harder to reason about and test for strict parsing invariants.
  - Current implementation routes peer-store validation and listing through typed Rust ops commands with custody checks and fail-closed parsing.
- Recommended hardening:
  - Keep strict custody on create/write (`0600`, owner-only, non-symlink regular file only).
  - Keep delimiter/control-character rejection for all persisted peer fields.
  - Preserve one-path policy: `start.sh` must use Rust peer-store ops rather than direct shell file parsing.
- Status: `Mitigated on 2026-03-07 (active peer-store validation/read paths migrated to Rust ops commands; shell parsing path removed from active start.sh peer-store flow)`

### F-03: Privileged helper token policy is broad and not command-schema specific
- Severity: `High`
- Evidence:
  - `crates/rustynetd/src/privileged_helper.rs:454`
  - `crates/rustynetd/src/privileged_helper.rs:481`
  - `crates/rustynetd/src/privileged_helper.rs:486`
- Why this matters:
  - Helper executes high-privilege networking commands.
  - Generic token allow-list still permits punctuation like `;`, `{`, `}`; argv-only execution avoids shell injection, but command-specific parser abuse remains a future risk if callers loosen validation.
- Recommended hardening:
  - Replace generic token checks with per-program/per-subcommand schemas.
  - Reject all punctuation not required by that exact schema.
  - Add negative tests for parser-level argument smuggling.
- Status: `Mitigated on 2026-03-07 (strict per-command nft/ip/wg/etc schemas + negative tests)`

### F-04: E2E remote orchestration shell-execution risk (historical)
- Severity: `Medium`
- Evidence:
  - `scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh:9`
  - `crates/rustynet-cli/src/main.rs:517`
  - `crates/rustynet-cli/src/ops_e2e.rs:789`
  - `crates/rustynet-cli/src/ops_e2e.rs:2359`
  - `crates/rustynet-cli/src/ops_e2e.rs:2401`
  - `crates/rustynet-cli/src/ops_e2e.rs:2412`
  - `crates/rustynet-cli/src/ops_e2e.rs:2489`
  - `crates/rustynet-cli/src/ops_e2e.rs:2527`
  - `crates/rustynet-cli/src/ops_e2e.rs:2639`
- Why this matters:
  - Prior implementation used remote shell snippet execution (`bash -se`) for privileged orchestration helpers.
  - Current implementation dispatches all active remote orchestration/probe steps via argv-based SSH command execution helpers and typed Rust ops subcommands.
- Recommended hardening:
  - Keep a single Rust entrypoint (`rustynet ops run-debian-two-node-e2e`) for orchestration.
  - Keep strict token/path validation for all dynamic remote arguments.
  - Preserve test coverage that guards against reintroducing shell payload execution paths.
- Status: `Mitigated on 2026-03-07 (legacy shell orchestrator, remote bash payload scripts, and SSH shell-snippet helpers removed from active path; active orchestration uses argv-only remote command dispatch with typed Rust ops subcommands)`

### F-05: Phase readiness artifacts are validated structurally but not cryptographically
- Severity: `High`
- Evidence:
  - `scripts/ci/check_phase10_readiness.sh:31`
  - `scripts/ci/check_phase10_readiness.sh:40`
  - `scripts/ci/check_phase10_readiness.sh:54`
  - `scripts/ci/check_phase10_readiness.sh:64`
- Why this matters:
  - Gate checks require measured fields and freshness, but do not verify signature/provenance of source artifacts.
  - A forged artifact set can satisfy readiness checks if written to expected paths.
- Recommended hardening:
  - Sign source and derived evidence artifacts.
  - Bind signature metadata to host identity, command digest, and capture time.
  - Fail closed when signature verification is missing or invalid.
- Status: `Mitigated on 2026-03-07 (signed phase10 provenance attestation + fail-closed verification gate)`

### F-06: Some security helper APIs are publicly exposed without current external use
- Severity: `Low`
- Evidence:
  - `crates/rustynet-control/src/admin.rs:97`
  - `crates/rustynet-control/src/admin.rs:202`
  - `crates/rustynet-control/src/admin.rs:216`
  - `crates/rustynet-control/src/admin.rs:260`
  - helper APIs are now test-only (`#[cfg(test)]`) and no longer exported in production builds.
- Why this matters:
  - Unnecessary `pub` surface grows misuse risk and compatibility burden.
  - Makes future hardening/refactoring harder because external use becomes accidental API contract.
- Recommended hardening:
  - Tighten visibility to `pub(crate)` or private for helper-only APIs.
  - Keep exported interfaces minimal and intentional.
- Status: `Mitigated on 2026-03-07 (helper APIs moved to test-only scope; production export surface reduced)`

### F-07: Numeric security configuration is runtime-validated but not type-level constrained
- Severity: `Low`
- Evidence:
  - `crates/rustynetd/src/daemon.rs:205`
  - `crates/rustynetd/src/daemon.rs:216`
  - `crates/rustynetd/src/daemon.rs:217`
  - `crates/rustynetd/src/daemon.rs:218`
  - `crates/rustynetd/src/daemon.rs:221`
  - `crates/rustynetd/src/main.rs:448`
  - `crates/rustynetd/src/main.rs:552`
  - `crates/rustynetd/src/main.rs:564`
  - `crates/rustynetd/src/main.rs:576`
  - `crates/rustynetd/src/main.rs:587`
- Why this matters:
  - Numeric constraints are now mostly encoded at the type level, reducing invalid-value propagation and parser regression risk.
  - Type-level constraints reduce parser mistakes/regressions.
- Recommended hardening:
  - Keep `NonZero*` type constraints for timeout/interval/count fields.
  - Introduce typed CIDR collections instead of `Vec<String>` where feasible.
- Status: `Mitigated on 2026-03-07 (core timeout/interval/count settings use NonZero* and fail-closed SSH allow CIDRs now use typed ManagementCidr values parsed and validated before daemon runtime)`

### F-08: Control-plane signing seed derivation is domain-separated but still custom KDF logic
- Severity: `Medium`
- Evidence:
  - `crates/rustynet-control/src/lib.rs:31`
  - `crates/rustynet-control/src/lib.rs:1512`
  - `crates/rustynet-control/src/lib.rs:2012`
  - `crates/rustynet-control/src/lib.rs:3013`
- Why this matters:
  - Previous approach (`SHA256(domain || secret)`) was deterministic and domain-separated, but bespoke.
  - Migrating to standard HKDF semantics improves cryptographic reviewability and future extensibility.
- Recommended hardening:
  - Replace with HKDF-SHA256 (`salt`, `info/domain`) and versioned derivation labels.
  - Add deterministic test vectors to prevent silent derivation drift.
- Status: `Mitigated on 2026-03-07 (HKDF-SHA256 derivation with fixed salt/info labels + deterministic test vectors)`

## 2) Lessons From Comparable Projects (Attacks + Patches)

### L-01: TunnelCrack (2023) - tunnel bypass across many VPN clients
- What happened:
  - Researchers showed practical tunnel bypass attacks (`LocalNet` and `ServerIP`) affecting many VPN apps.
- How projects patched:
  - Hardened route handling around local network trust and VPN server path exceptions.
  - Reduced client behavior that trusted attacker-controlled local routing context.
- Rustynet lesson:
  - Keep strict route ownership and deny ad-hoc local route exceptions unless cryptographically authorized.
- Source:
  - [TunnelCrack site](https://tunnelcrack.mathyvanhoef.com/)
  - [USENIX paper](https://www.usenix.org/conference/usenixsecurity23/presentation/vanhoef)

### L-02: TunnelVision (CVE-2024-3661) - DHCP option 121 route injection bypass
- What happened:
  - Attackers on local network can push classless routes (DHCP option 121) that bypass VPN traffic.
- How projects patched/mitigated:
  - Moved toward stronger route isolation models.
  - Emphasized namespace-based designs that are less dependent on mutable host routing tables.
- Rustynet lesson:
  - Prefer namespace/interface isolation for fail-closed guarantees.
  - Treat host-route table trust as weak in hostile LANs.
- Source:
  - [Leviathan TunnelVision disclosure](https://www.leviathansecurity.com/blog/tunnelvision)
  - [WireGuard netns guidance](https://www.wireguard.com/netns/)

### L-03: OpenVPN VORACLE - compression side-channel leakage
- What happened:
  - Compression enabled traffic analysis attacks against secret-bearing streams.
- How projects patched:
  - Compression disabled/deprecated in secure defaults and guidance.
- Rustynet lesson:
  - Keep “feature” paths off by default when they weaken confidentiality.
  - Continue explicit prohibition on optional insecure transport features.
- Source:
  - [OpenVPN VORACLE advisory](https://openvpn.net/security-advisory/the-voracle-attack-vulnerability/)

### L-04: OpenVPN Access Server CVE-2025-13086 - malformed request DoS
- What happened:
  - Malformed requests could crash `asd` in some configurations.
- How projects patched:
  - Vendor release with fixed parser/handling (`3.0.2`).
- Rustynet lesson:
  - Keep parser hardening and negative tests for malformed control-plane requests.
  - Treat crashable parser paths as security issues (availability is part of security).
- Source:
  - [OpenVPN Access Server advisory](https://openvpn.net/security-advisory/access-server-security-update-cve-2025-13086/)

### L-05: strongSwan CVE-2022-4967 - authorization bypass via X.509 handling edge case
- What happened:
  - Specific certificate/identity handling could permit impersonation in some setups.
- How projects patched:
  - Fixed in upstream release (`5.9.6`) and documented affected versions.
- Rustynet lesson:
  - Keep identity binding checks strict and explicit in certificate-backed trust flows.
  - Add regression tests for malformed/edge-case identity chains.
- Source:
  - [strongSwan CVE-2022-4967 advisory](https://www.strongswan.org/blog/2023/01/30/strongswan-vulnerability-%28cve-2022-4967%29.html)

### L-06: Tailscale TS-2025-008 - fail-open signer checks when state dir unavailable
- What happened:
  - If state storage was unavailable, signing checks could be bypassed and update checks disabled.
- How projects patched:
  - Fixed startup/update behavior and tightened state handling in subsequent releases.
- Rustynet lesson:
  - Never fail open on missing trust/signing state.
  - Missing security state must produce hard startup failure.
- Source:
  - [Tailscale security bulletins](https://tailscale.com/security-bulletins)

### L-07: Tailscale TS-2026-001 - shell command injection in privileged launch path
- What happened:
  - A local root-command path used `/bin/sh -c` with username templating, enabling command injection.
- How projects patched:
  - Reworked release to remove vulnerable command construction path.
- Rustynet lesson:
  - Reinforces current direction: no shell construction in privileged paths, argv-only execution only.
- Source:
  - [Tailscale security bulletins](https://tailscale.com/security-bulletins)

## 3) Security Hardening Checklist (Prioritized)

### Immediate
- Remove/replace shell break-glass dataplane mutation in `start.sh` with signed Rust command path. (`Completed by removing manual shell mutation path on 2026-03-06`)
- Introduce cryptographic provenance checks for phase evidence artifacts. (`Completed on 2026-03-07: signed Phase10 provenance attestation + mandatory verification`)
- Tighten privileged helper argument validation to per-command schema. (`Completed on 2026-03-07: strict program/subcommand schemas + negative tests`)

### Near-term
- Collect Linux VM validation evidence for recent security migrations (`F-02`, `F-04`) and keep CI/runtime regression checks green.

### Quick wins
- Minimize public API surface in `rustynet-control/src/admin.rs`. (`Completed on 2026-03-07`)
- Upgrade key numeric fields to `NonZero*` types and typed CIDR wrappers. (`Completed on 2026-03-07`)

## 4) Notes on Existing Strengths
- Rustynet already enforces several strong controls (fail-closed defaults, signed trust handling, key custody hardening).
- Recent high-value shell-to-Rust security migrations (`F-02`, `F-04`) are now implemented; remaining work is operational validation evidence on Linux VM matrix.

## References
- [TunnelCrack](https://tunnelcrack.mathyvanhoef.com/)
- [TunnelCrack USENIX paper](https://www.usenix.org/conference/usenixsecurity23/presentation/vanhoef)
- [TunnelVision disclosure](https://www.leviathansecurity.com/blog/tunnelvision)
- [WireGuard netns integration](https://www.wireguard.com/netns/)
- [OpenVPN VORACLE advisory](https://openvpn.net/security-advisory/the-voracle-attack-vulnerability/)
- [OpenVPN CVE-2025-13086 advisory](https://openvpn.net/security-advisory/access-server-security-update-cve-2025-13086/)
- [strongSwan CVE-2022-4967 advisory](https://www.strongswan.org/blog/2023/01/30/strongswan-vulnerability-%28cve-2022-4967%29.html)
- [Tailscale security bulletins](https://tailscale.com/security-bulletins)
