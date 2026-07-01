# Live-Lab Security Test Coverage & Threat Matrix — 2026-06-22

Status: **active**. Owner track: security test engineering. Branch:
`claude/livelab-security-tests` (original); reprioritized + extended
2026-07-01 on `claude/cross-platform-parity-hardening`.

## Priority order — build sequence (reprioritized 2026-07-01)

The full backlog below (§2.4, 111 confirmed-implementable gaps) is organized
by surface, not by priority. This section is the build order — cross-checked
2026-07-01 against the current orchestrator stage catalog, `SecurityMinimumBar`/
`Requirements`, every active execution ledger, the MCP orchestration surface,
and the lab-monitor GUI schema, then verified against the actual code (not
taken on a report's word — see the inline verification notes below and in
Phase 3, §9). Stage IDs are the ones already assigned below; this section
orders them, it does not invent new ones.

### Tier 0 — verify the two already-fixed CRITICAL bugs (build first)

Both are already fixed in code but have **zero live-lab proof**, so revocation
being "done" currently rests on unit tests alone:

1. **RSA-0009** → `validate_linux_membership_revoke_applies` — apply a signed
   Revoke/RotateKey/Restore/SetCapabilities update against a live daemon,
   assert it lands. Fix (`a23df5f`, 2026-06-24) verified present in
   `crates/rustynet-control/src/membership.rs::reduce_membership_state` as of
   2026-07-01: the function now takes `op_created_at_unix: u64` and stamps it
   instead of calling `unix_now()` — the nondeterministic-state-root bug
   described in FINDING-A (§2.1) is closed in code.
2. **DD-03** → `validate_linux_revoked_peer_denied_e2e` — revoke a live peer,
   then prove its real WireGuard traffic is denied by dataplane/exit/LAN ACL
   admission, not just that its config went stale. Fix (`92e5748`,
   2026-06-24) verified present as of 2026-07-01: both ACL call sites in
   `crates/rustynetd/src/phase10.rs` (`set_exit_node`, `ensure_lan_route_allowed`)
   now call `evaluate_with_membership`; no remaining production call to the
   membership-blind `evaluate()` exists in `rustynetd` (the one hit,
   `policy_default_deny_audit.rs:198`, is the truth-table audit harness
   deliberately exercising both evaluators for comparison, not a trust
   decision path).

### Tier 1 — adversarial stages that attack a control, not just exercise it

In rough priority order; all IDs already carry full spec + bite-test in §2.4:

| Priority | ID | Stage | Attacks |
|---|---|---|---|
| 1 | GM-1 | `validate_linux_gossip_revoked_readmit` | Gossip re-admitting a revoked node — `ingest_inbound_bundle` never checks membership; defense-in-depth gap right next to DD-03 |
| 2 | ENR-1 | `validate_linux_enrollment_replay` | Presenting an already-consumed enrollment token again |
| 3 | TOCTOU-1 | `validate_linux_enrollment_concurrent_consume` | Two processes redeeming one token simultaneously (RSA-0023, no file lock on the ledger) |
| 4 | DOS-1 | `validate_linux_relay_hello_node_id_flood` | Unauthenticated memory exhaustion via relay `HelloLimiter` (RSA-0037, confirmed-unbounded map) |
| 5 | RT-2 | `validate_linux_blind_exit_reversal_denied` | Every non-blind_exit transition after going blind — today only the "stays blind_exit" positive path is proven |
| 6 | RR-01/02/03 | `validate_linux_replay_persistence` (+ traversal/enrollment variants) | Replaying a stale/consumed bundle after reboot — watermark is in-memory only (RSA-0029) |
| 7 | FCF-1/2/3 | `validate_linux_crash_midapply_failclosed` / `_corrupt_state_failclosed` / `_keystore_unavailable_failclosed` | `kill -9` mid-signed-state-write, truncated trust state, locked keystore — daemon must refuse to boot into an inconsistent trust state |
| 8 | RPT-01 | `validate_linux_relay_ciphertext_only` | **See correction below — this is currently the ONLY relay-forwarding proof of any kind on any OS, not just the ciphertext-only property** |
| 9 | S3-10 | `validate_macos_codesign` (+ Windows Authenticode deploy-time equivalent) | Tampered/unsigned binary landing on a node — today's checks are CI-gate-only |
| 10 | RSA-0063 | `validate_macos_bootstrap_privesc_residue` | Leftover `NOPASSWD: ALL` sudoers file after a failed Homebrew install — confirmed-present, CRITICAL/High severity, zero coverage |
| 11 | KC-04 | Windows key-custody negative path | `validate_key_custody_permissions` no-ops on non-Unix (RSA-0002) — a world-readable key silently passes on Windows |
| 12 | PH-7 | `validate_macos_privileged_helper_allowlist` | Same adversarial argv corpus already proven on Linux, ported to `pfctl` |
| 13 | KL-2/KL-3/KL-4 | macOS/Windows killswitch-leak parity | Linux now has full v4+v6 active-probe+capture; other OSes don't |
| 14 | KC-07 | macOS/Windows secrets-not-in-logs parity | Linux-only today; the Linux gate is also currently RED (RSA-0080 — macOS bootstrap `rm -f`'s the WG passphrase, no secure-erase) — fix alongside |
| 15 | CNT-1 | `validate_linux_upnp_ssrf` | Confirmed-present SSDP LOCATION/controlURL SSRF (RSA-0035), zero live coverage |
| 16 | PH-2/PH-3 | Privileged-helper live socket fuzz + cross-UID rejection | Today's helper coverage is argv-only — nothing attacks the live IPC socket itself |

**Correction to item 8 / §3 vuln-class-8, verified 2026-07-01:** the existing
"✅ forwarding" coverage claim for relay is not accurate. `live_linux_relay_test.rs`
proves the systemd/launchd unit is active, `/healthz` answers, and stop/uninstall
cleanly tears down — service **lifecycle** only, no traffic. `live_linux_two_hop_test.rs`
tests `client → entry(also serving exit) → final_exit → internet` — exit-role
*chaining*, a different subsystem from the dedicated `rustynet-relay`
frame-forwarding service. **No stage on any OS has ever driven a real peer's
session through the relay role and proven a frame was forwarded.** This was
already flagged once (`LiveLabCoverageAndHonestyAudit_2026-06-25.md` findings
#7/#8) and partially addressed since — the two-hop test now does a real ICMP
probe + per-hop TTL-delta measurement (not just status-string checks), and
relay lifecycle is now genuinely live-proven (not dry-run-as-pass) — but the
frame-forwarding property itself is still unproven. This is the same gap
tracked as `HP-3` in `MasterWorkPlan_2026-03-22.md` and
`CrossPlatformRoleParityRoadmap_2026-06-22.md` ("most substantial remaining
code item"). RPT-01 above is the closest existing spec; building it (or a
plain `validate_linux_relay_forwards_frame` proof first, with ciphertext-only
as a follow-on assertion) closes both RPT-01 and HP-3 at once.

### Tier 2 — larger, infra-gated items (design mostly done, needs a prerequisite first)

- **HP-3 relay live packet-forwarding proof** — see correction above; arguably
  the single biggest "looks done but isn't" gap in the whole matrix.
- **nas/llm M5 live evidence chain** (deploy→authorize→use→revoke→undeploy) —
  last milestone blocking the service-hosting program
  (`ServiceHostingRolesRoadmap_2026-06-11.md`).
- **Cross-network NAT-profile substrate (X1–X3)** — needed before
  `cross_network_cold_enroll`/`anchor_renumber`/`double_nat_anchor` can produce
  real evidence instead of `fail`-by-default
  (`CrossNetworkSubstrateIntegrationSpec_2026-06-21.md`).
- **Real cross-OS role-switch** — macOS/Windows actually flipping role, not
  just "tunnel stays up" (`CrossOsRoleSwitchPlan_2026-06-24.md` exists, no
  stage yet).

### Needs verification, not a build item — check before trusting

- **CPA-1** (`validate_linux_audit_chain_integrity`) is marked ✅DONE in §2.3,
  but a 2026-07-01 grep of `crates/rustynet-cli/src/vm_lab/mod.rs` and
  `crates/rustynet-cli/src/bin/` found **zero references** to
  `audit_chain_integrity` anywhere in the orchestrator. Either a standalone
  e2e script exists outside those paths and wasn't found, or the ✅DONE marker
  is wrong. Confirm one way or the other before relying on it — do not
  re-mark it done again without finding the actual wired stage.

Full mechanics for wiring any of the above into the orchestrator, both MCP
servers, and the lab-monitor GUI: Phase 3, §9 below.

## 0) Purpose & scope

This document is the threat-coverage map for Rustynet's **adversarial
live-lab** security tests. For every vulnerability class and every
`SecurityMinimumBar.md` control it records: what the control defends, the
existing coverage (live-lab stage / e2e wrapper / CI gate / unit test), the
**new adversarial test added on this branch**, and the **gaps** still open
(with a proposed test or a documented lab/env blocker).

The guiding rule (from the mission and `CLAUDE.md` §7/§9): for every control,
ask "how would I break this?", write a stage that *attempts* the exploit, and
assert the system **fails closed**. A test that can never fail is worthless —
each new validator carries a tampered-input negative test that proves it bites.

### Isolation note (why nothing here was run live)

A live-lab `orchestrate` run was in progress in a separate worktree when this
work was done. Per the mission, this branch **builds and unit-gates** the test
code only; it does **not** drive the VMs. Each new stage is gated to **Skip
cleanly** in a default run and documents exactly how to execute it live (§7).
The unit tests prove every new validator's correctness and bite without the VMs.

### FAIL-LOUD contract (restated)

The **live** result IS the stage status. A dry-run / contract check is never a
`Pass` — it is `Skipped`/informational. A stage that cannot run live `Skip`s,
never silently `Pass`es. Every new stage can genuinely `Fail` when the defence
is absent (proven by the negative unit tests in §6).

## 1) Methodology (applied per test)

Each entry below was built by:
- **(a)** identifying the control + the exact `SecurityMinimumBar`/`Requirements`
  clause it defends;
- **(b)** checking whether a live-lab stage already exercises it (`grep` over
  `crates/rustynet-cli/src/vm_lab` + `scripts/e2e` + `scripts/ci`);
- **(c)** if not, implementing an adversarial stage that performs the attack on
  the guest, captures evidence, and asserts fail-closed — reusing the
  established `stage_outcome` / `capture_remote_shell_command_for_target` /
  `rustynetd <capture|verify>` subcommand patterns, argv-safe;
- **(d)** proving the test bites with a tampered-input unit test over the
  validator (tampered → reject, clean → accept);
- **(e)** where a genuine weakness was found, documenting it as a finding
  (§5) rather than silently changing production code.

## 2) Research summary — industry rigor borrowed

How mature projects test these exact properties, and what this suite adapted:

- **Tailscale** ships ACL **policy tests inside the policy file** (a top-level
  `tests` block) so a control-plane change is validated *before* it is applied,
  and runs them in CI via the GitOps ACL action in test-only vs apply modes.
  Adapted here as: default-deny ACL truth-table unit tests run as CI gates
  (`llm_default_deny_gates.sh`, `nas_default_deny_gates.sh`) **plus** the
  live `validate_linux_*` posture stages that re-assert the deployed posture.
  ([tailscale ACL tests](https://tailscale.com/kb/1018/acls),
  [gitops-acl-action](https://github.com/tailscale/gitops-acl-action))
- **WireGuard** is **formally verified in the symbolic model with Tamarin**
  (Donenfeld & Milner) and mechanised in CryptoVerif, covering the IK Noise
  handshake and the cookie/DoS messages. Rustynet treats WireGuard as a
  black-box adapter (no custom crypto), so the live tests target *integration*
  failure modes the proofs don't cover: endpoint hijack
  (`real_wireguard_rogue_path_hijack_e2e.sh`,
  `live_linux_endpoint_hijack_test.sh`), signed-state tamper around the
  handshake (`real_wireguard_signed_state_tamper_e2e.sh`), and leak under load.
  ([WireGuard formal verification](https://www.wireguard.com/formal-verification/),
  [Unified symbolic analysis of WireGuard (NDSS)](https://www.ndss-symposium.org/ndss-paper/a-unified-symbolic-analysis-of-wireguard/))
- **The VPN "leak test" canon** checks five layers — IPv4, **IPv6**, DNS,
  WebRTC, and killswitch — and the classic failure is *IPv4 routed correctly
  while native IPv6 bypasses the tunnel entirely*. Rustynet had **no IPv6 leak
  coverage at all**; this branch adds the IPv6 tunnel-leak stage (§4.1, §5
  GAP-1) modelled on that canon (active probe + egress capture + posture).
  ([Mullvad connection check](https://mullvad.net/en/check),
  [Testing for IPv6 VPN leaks](https://oneuptime.com/blog/post/2026-03-20-test-ipv6-vpn-leaks/view))
- **Nebula** evaluates its firewall rules against certificate metadata at
  handshake time, and — critically — a real CVE class shows attackers
  **bypassing its certificate revocation list via ECDSA P256 signature
  malleability**. This is the exact threat Rustynet's RN-22 standard
  (`ed25519 verify_strict` everywhere; `security_regression_gates.sh` G3,
  RSA-0077/0043) defends against. The coverage matrix treats malleable
  signature acceptance as a first-class adversarial case.
  ([Nebula certificate system](https://deepwiki.com/slackhq/nebula/4.1-certificate-system),
  [CVE-2026-25793 Nebula auth bypass](https://www.sentinelone.com/vulnerability-database/cve-2026-25793/))
- **ZeroTier** propagates membership **revocations peer-to-peer via a rumor-mill**
  with a moving-window certificate-timestamp scheme (no clock sync). The
  analogue here — signed-gossip + revocation freshness, and replay/rollback
  watermarks surviving restart — is covered by `live_chaos_membership_adversarial`
  / `live_chaos_clock_attack` and flagged for a cross-reboot replay stage
  (§5 GAP-3). ([ZeroTier protocol](https://docs.zerotier.com/protocol/))
- **NetBird / Firezone** are default-deny ("access denied until a policy
  allows it") over WireGuard with ICE/STUN traversal and relay fallback —
  validating Rustynet's own default-deny + traversal-adversarial posture
  (`traversal_adversarial_gates.sh`,
  `live_linux_cross_network_traversal_adversarial_test.sh`).
  ([NetBird how it works](https://docs.netbird.io/about-netbird/how-netbird-works))
- **Methodology frameworks**: MITRE ATT&CK (network) + OWASP-style negative
  testing inform the per-control "attempt the exploit" stages; property/fuzz
  testing (the existing `fuzzgate_*` privileged-helper cases, RSA-0038/0040/0042
  cargo-fuzz targets) and chaos/soak (the `live_chaos_*` suite) cover the
  fail-closed-under-fault dimension.

## 3) Threat-coverage matrix (vuln class × control × coverage)

Legend — Coverage: ✅ live-lab stage exists · 🧪 unit/gate only (no live
adversarial stage) · 🆕 added on this branch · ⚠️ gap (see §5).

| # | Vuln class | SecMinBar control | Existing coverage | This branch | Status |
|---|---|---|---|---|---|
| 1 | Signature forgery / tamper | §3.2, §6.B, §6.C.1 | `real_wireguard_signed_state_tamper_e2e.sh`, `live_chaos_signed_state_adversarial`; unit: `bundle_with_tampered_signature_rejected_*` (control), `verify_bundle_rejects_tampered_signature` (dns-zone); gate: `security_regression_gates.sh` G3 (`verify_strict`/RN-22) | — | ✅ |
| 2 | Replay / rollback / watermark | §3.3, §4 (anti-replay), §6.C.5 | `live_chaos_clock_attack`; unit: `PerEpochReplayWatermark::validate_bundle`, membership pre/post-rotation tests, `enrollment_token` consumed-ledger | — | ✅ runtime; ⚠️ **cross-reboot** persistence not a dedicated live stage (GAP-3; RSA-0029/0079) |
| 3 | Downgrade / protocol confusion | §3 (one hardened path) | `security_regression_gates.sh` (deprecated-crypto ban G2a/b/c), backend-boundary gate; anchor-downgrade unit (§6.C.5) | — | 🧪 (no dedicated downgrade *live* stage; low marginal risk) |
| 4 | Default-deny bypass (ACL/route/cap) | §3.6, §6.E.2 | gates: `llm_default_deny_gates.sh`, `nas_default_deny_gates.sh`; unit: `policy_defaults_to_deny`, revoked-node-denied; live: `live_linux_server_ip_bypass_test.sh`, `live_linux_control_surface_exposure_test.sh` | — | ✅ |
| 5 | Fail-open under failure | §3.4, §4 (fail-closed) | `live_chaos_crash_recovery`, `live_chaos_daemon_fault`, `live_chaos_resource_exhaustion`; `force_fail_closed_or_restrict` | — | ✅ |
| 6 | Killswitch / traffic leak (v4 **&v6**) | §3.8, §6 (leak tests) | v4: `real_wireguard_no_leak_under_load.sh`, `capture_*_exit_killswitch_precedence`, `no_leak_dataplane_gate.sh`, `live_linux_path_handoff_under_load_test.sh` | **🆕 `validate_linux_ipv6_leak`** (IPv6 leak) | ✅ v4; **🆕 v6 (was ⚠️ GAP-1)**; ⚠️ v6 macOS/Windows parity (GAP-4) |
| 7 | DNS leak / DNS fail-closed | §3.8, §6 | `validate_{linux,macos,windows}_exit_dns_failclosed`, `validate_*_dns_failclosed`, `live_*_managed_dns_test.sh` | — | ✅ (A records); ⚠️ AAAA/IPv6-DNS not separately asserted (GAP-4) |
| 8 | Relay-sees-plaintext | §3 (relay), Dataplane plan | `live_linux_relay_test.rs` (service lifecycle: active/`healthz`/clean stop, live-proven, not dry-run); `live_linux_two_hop_test.sh` (separate subsystem — exit-role chaining, real ICMP+TTL-delta probe); relay zero-copy forward unit | — | ⚠️ **corrected 2026-07-01**: relay *lifecycle* ✅ live-proven; relay *frame-forwarding* is ⚠️ unproven on every OS — no stage has ever driven a real peer's session through the relay role (see priority-order section above, RPT-01/HP-3). Previous "✅ forwarding" here conflated lifecycle + an unrelated exit-chaining test with actual relay forwarding. |
| 9 | Exit NAT residue | §6.D.7 | `validate_{linux,macos,windows}_exit_nat_lifecycle` (two-phase: present during / gone after); RSA-0031 teardown-verify | — | ✅ |
| 10 | Privilege escalation / helper abuse | §3.7, §7 (argv-only) | unit: 36 `validate_request` adversarial cases + `fuzzgate_*`; live: `live_chaos_privileged_boundary` | **🆕 `validate_linux_privileged_helper_allowlist`** (corpus vs real allowlist, FAIL-LOUD, per-OS) | ✅ + **🆕 orchestrator-integrated stage** |
| 11 | Role-transition abuse | §6.D | gates: `role_taxonomy_gates.sh`, `role_transition_audit_gates.sh`, `blind_exit_irreversibility_gates.sh`; live: `live_*_role_switch_matrix_test.sh` | — | ✅ |
| 12 | Enrollment-token abuse | §3.3, §6.C.3 | unit: `enrollment_token` single-use ledger, oversize-reject, HMAC const-time; live: `live_linux_enrollment_restart_test.sh` | — | ✅ runtime; ⚠️ cross-process consume race is in-test (RSA-0023) |
| 13 | Membership / gossip poisoning | §6.B, §6.C.1 | `live_chaos_membership_adversarial`, `live_chaos_signed_state_adversarial`; gossip `verify_strict` | — | ✅; 🧪 RSA-0034 gossip re-check-membership is defense-in-depth |
| 14 | Key custody / secret leakage | §3.4, §4, §6.C.4 | live: `live_linux_key_custody_test.sh`, `live_linux_secrets_not_in_logs_test.sh`, `validate_*_key_custody`; gates: `secrets_hygiene_gates.sh`, `anchor_secret_redaction_gates.sh` | — | ✅; ⚠️ Windows read-side perm no-op (RSA-0002) |
| 15 | MITM / handshake | §3.1/§3.2, §3.8 | `real_wireguard_rogue_path_hijack_e2e.sh`, `live_linux_endpoint_hijack_test.sh` | — | ✅ |
| 16 | TOCTOU / races | §3 (deterministic state), §6.C.3 | unit: role-audit hash-chain TOCTOU (RSA-0012), enrollment-consume race; `live_chaos_crash_recovery` | — | ✅ runtime; 🧪 some race finds are unit-only |
| 17 | Resource exhaustion / DoS | §4 High (relay abuse/capacity) | `live_chaos_resource_exhaustion`; unit: relay `HelloLimiter`, oversize-reject, MCP/LLM read caps | — | ✅; ⚠️ relay HelloLimiter unbounded map (RSA-0037) — no live bound-assertion (GAP-5) |
| 18 | Cross-network / NAT-traversal abuse | §3.8 (traversal), Dataplane plan | `live_linux_cross_network_traversal_adversarial_test.sh`, `traversal_adversarial_gates.sh`, cross-network suite | — | ✅; ⚠️ post-restart traversal replay window (RSA-0029, GAP-3) |

## 4) New adversarial tests added on this branch

### 4.1 `validate_linux_ipv6_leak` — IPv6 tunnel-leak (vuln class 6, SecMinBar §8)

- **Producer**: `rustynetd::linux_ipv6_leak` + `rustynetd linux-ipv6-leak-capture`.
  In a protected mode it runs a **real outbound IPv6 probe** to a global
  address while `tcpdump` watches the egress interface with a BPF filter that
  excludes link-local (`fe80::/10`) + multicast (`ff00::/8`) — so any captured
  datagram is a genuine cleartext leak — and records the IPv6 containment
  posture (`net.ipv6.conf.all.disable_ipv6` / an `inet`/`ip6` killswitch drop).
- **Validator**: `evaluate_linux_ipv6_leak_artifact` (vm_lab). **Fails closed**
  if any datagram leaked, if the probe reached its target, or if *no*
  containment control is present (an IPv4-only `table ip` killswitch does **not**
  count — that is the exact bug).
- **Stage**: Skip-by-default unless the live artifact
  `linux_exit_evidence/linux_ipv6_leak.json` is present; FAIL-LOUD on validation.
- **Wrapper**: `scripts/e2e/capture_linux_ipv6_leak.sh`.
- **Bite proof (unit)**: leaked-datagram / probe-reached / no-containment /
  IPv4-only-killswitch all reject; clean fail-closed posture accepts; producer→
  validator round-trip both directions.

### 4.2 `validate_linux_privileged_helper_allowlist` — argv-allowlist self-audit (vuln class 10, SecMinBar §7)

- **Producer**: `rustynetd::privileged_helper_allowlist_audit` +
  `rustynetd privileged-helper-allowlist-audit`. Drives the **real shipped**
  `privileged_helper::validate_request` with an adversarial-plus-benign corpus
  (path traversal, anchor-name escape, injection metacharacters, arbitrary
  sysctl keys/values, non-owned nft tables, `kill` pid 1 / non-`-TERM`, unknown
  program, empty/oversized argv) and asserts every adversarial request is
  **denied** while every reviewed request is still **allowed** (not a trivial
  deny-all). Exits non-zero on any violation.
- **Validator**: `evaluate_privileged_helper_allowlist_report` (vm_lab).
- **Stage**: gated on `validate_linux_runtime_acls`; default dry-runs Skip.
- **Bite proof (unit)**: fails if an adversarial case is accepted
  (privilege-escalation regression) *or* a reviewed case is rejected
  (control-plane breakage); corpus validated against the real validator so it
  holds without VMs.

Both stages integrate with `live_lab_run_matrix` accounting and the per-alias
Linux stage list.

## 5) Findings / open gaps (with proposed tests)

- **GAP-1 — IPv6 tunnel leak (CLOSED on this branch).** Severity High. No
  killswitch/no-leak test exercised IPv6; an IPv4-only killswitch would let
  native IPv6 egress in the clear (SecMinBar §8). Repro: bring the tunnel up
  with an IPv4 killswitch and `ping -6` a global address — pre-fix, traffic
  egresses. **Fix: §4.1.** Regression unit tests added.
- **GAP-2 — privileged-helper allowlist had no FAIL-LOUD orchestrator stage
  (CLOSED on this branch).** Severity Medium (defense-in-depth/assurance; unit
  coverage already strong). **Fix: §4.2.**
- **GAP-3 — cross-reboot replay/rollback persistence has no dedicated live
  stage.** Severity Medium. Maps RSA-0029 (traversal coordination replay window
  is in-memory only; 24h TTL allows post-restart replay) and RSA-0079
  (fresh-enroll bootstrap wipes the anti-replay watermark). Proposed:
  `validate_linux_replay_persistence` — capture watermark, reboot the node,
  re-present a lower-epoch / previously-consumed bundle, assert rejection
  persists across reboot. Add a daemon `*-watermark-snapshot` verify subcommand.
- **GAP-4 — IPv6 parity for the leak/DNS stages.** Severity Medium. §4.1 covers
  Linux; macOS (pf `block drop`/`disable_ipv6` analogue) and Windows (WFP)
  need the same stage, and DNS fail-closed should assert AAAA as well as A.
  Proposed: `validate_{macos,windows}_ipv6_leak` mirroring §4.1; extend the
  DNS-failclosed validators with an AAAA negative probe.
- **GAP-5 — relay unauthenticated DoS bound has no live assertion.** Severity
  Medium. Maps RSA-0037 (relay `HelloLimiter` per-`node_id` map is never pruned
  or capped → memory-exhaustion). `live_chaos_resource_exhaustion` exercises
  generic exhaustion but not this specific bound. Proposed: a relay-flood stage
  that drives many distinct `node_id` hellos and asserts bounded memory +
  fail-closed (node stays up, does not OOM).

### RSA-ledger mapping note

The `SecurityAuditLedger_2026-06-18.md` is a **review-only** audit (every
finding tagged `open` = *raised*, with severity). This branch's base
(`origin/main` @ 4d14240, 2026-06-22) **postdates** that audit, so several
findings (e.g. RSA-0077/RSA-0043 `verify_strict`) are already code-fixed and
gated (`security_regression_gates.sh` G3). Confirming each finding's current
code state and attaching a regression test is tracked as follow-up; the
findings with **no live adversarial stage** are surfaced as GAP-3/4/5 above.
The remaining open findings are predominantly defense-in-depth / assurance
(severity Low/Info/Medium) with an existing enforcement point + unit/gate.

## 6) Proof the new validators bite (run without the lab)

```
cargo test -p rustynetd --lib linux_ipv6_leak
cargo test -p rustynetd --lib privileged_helper_allowlist_audit
cargo test -p rustynetd --bin rustynetd linux_ipv6_leak_capture
cargo test -p rustynetd --bin rustynetd privileged_helper_allowlist_audit
cargo test -p rustynet-cli --bin rustynet-cli ipv6_leak
cargo test -p rustynet-cli --bin rustynet-cli privileged_helper_allowlist
```

Each set includes a tampered/adversarial-input case that fails the validator
and a clean case that passes — the FAIL-LOUD guarantee.

## 7) How to run the new stages live

Both stages Skip in a default run. To exercise them live (after the in-progress
run completes — do not interrupt it):

### 7.1 IPv6 leak (`validate_linux_ipv6_leak`)

On a Linux node in a protected routing mode (tunnel + killswitch up), produce
the artifact, then run the Linux daemon validators:

```
# on the guest (or via the orchestrator's remote-shell), while protected:
sudo bash scripts/e2e/capture_linux_ipv6_leak.sh \
    --output "<report_dir>/linux_exit_evidence/linux_ipv6_leak.json"
# then, from the host, the validate-linux-security pass picks it up:
cargo run -p rustynet-cli -- ops vm-lab-validate-linux-security \
    --linux-vm debian-headless-1 --ssh-identity-file <id_ed25519> \
    --report-dir <report_dir>
# stage validate_linux_ipv6_leak → Pass (0 leaks, probe blocked, containment present)
#                               → Fail (leak observed / probe reached / no containment)
```

### 7.2 Privileged-helper allowlist (`validate_linux_privileged_helper_allowlist`)

Runs as part of the standard Linux daemon-validator chain — no artifact needed;
it invokes `rustynetd privileged-helper-allowlist-audit` on the guest:

```
cargo run -p rustynet-cli -- ops vm-lab-validate-linux-security \
    --linux-vm debian-headless-1 --ssh-identity-file <id_ed25519> \
    --report-dir <report_dir>
# stage validate_linux_privileged_helper_allowlist → Pass when the shipped
# allowlist denies every adversarial request and allows every reviewed one.
```

After any evidence run, verify the appended row in
`documents/operations/live_lab_run_matrix.csv` (both stages map to the
`linux/exit` and Linux daemon-validator cells via `live_lab_run_matrix.rs`).

---

# Phase 2 — Exhaustive multi-agent gap audit (2026-06-23)

A 42-agent adversarial workflow audited **21 security surfaces** (the 18 vuln
classes + a control-by-control `SecurityMinimumBar` sweep + an open-RSA-finding
sweep). Each surface got a deep mapper followed by an **adversarial verifier**
that challenged every claimed gap (greps for coverage the mapper missed; rejects
anything that would need a product backdoor or that wouldn't bite). Result:
**162 gaps reviewed → 111 confirmed-implementable** (2 critical, 50 high, 52
medium, 6 low, 1 info) + 3 backdoor/infeasible findings.

Methodology borrowed (see §2): Tailscale in-policy ACL tests, WireGuard Tamarin
verification, the VPN IPv4/IPv6/DNS leak canon, Nebula's ECDSA-malleability CRL
bypass (the real-world parallel to RN-22 `verify_strict`), ZeroTier rumor-mill
revocation, NetBird/Firezone default-deny.

## 2.1) Verified CRITICAL findings (first-hand, on this branch's code)

Two audit claims were verified directly against the current code and are
**release-blockers**. Per the operating contract §(e) they are SURFACED here
(not silently fixed — both touch the trust path and need owner review + lab
validation). Together they mean **node revocation is effectively non-functional**.

### FINDING-A (CRITICAL) — RSA-0009: membership Revoke/RotateKey/Restore/SetCapabilities can never apply

- **Where:** `crates/rustynet-control/src/membership.rs`. `reduce_membership_state`
  stamps `node.updated_at_unix = unix_now()` for the four trust-mutation ops
  (lines 1149 SetNodeCapabilities, 1168 RevokeNode, 1180 RestoreNode, 1193
  RotateNodeKey). `MembershipState::canonical_payload` hashes
  `node.{i}.updated_at_unix` into the state root (line 285), and
  `apply_signed_update` recomputes `new_state_root` and compares it to the
  record's (lines 721-723).
- **Mechanism:** the proposer reduces at T1 → `new_state_root` reflects
  `unix_now()=T1`; the applier reduces at T2 → recomputed root reflects
  `unix_now()=T2`. When `T1 != T2` (any wall-clock-second boundary) →
  `MembershipError::NewStateRootMismatch` → the op is rejected. `AddNode` is
  unaffected because it uses the record's own timestamp, which is why existing
  enroll/genesis tests pass and this slipped through. `reduce_membership_state`
  takes only `(&state, &operation)` and the `MembershipOperation` variants carry
  no timestamp, so the local `unix_now()` is the only source.
- **Impact:** revocation and key-rotation — the primary controls for withdrawing
  trust — cannot be applied in practice. Re-confirms AUDIT-040.
- **Repro (deterministic):** sign a `RevokeNode` record at T1 (its `new_state_root`
  computed by the reducer), apply it ≥1s later; `apply_signed_update` returns
  `NewStateRootMismatch`.
- **Proposed fix:** thread the signed record's `created_at_unix` into
  `reduce_membership_state` and stamp `updated_at_unix` from it (deterministic,
  signed), OR exclude `updated_at_unix` from `canonical_payload`/`state_root`.
  The first is surgical (only the four ops change; `AddNode`/genesis roots
  unchanged). Land with the deterministic regression test + a clock seam so the
  live `validate_linux_membership_revoke_applies` stage (audit RSA-0009) passes.
- **STATUS UPDATE (2026-07-01):** fix landed in `a23df5f` ("membership: make
  the reducer state-root deterministic so revocation applies"). Verified
  present in current code: `reduce_membership_state` now takes
  `op_created_at_unix: u64` and stamps it on `SetNodeCapabilities`/`RevokeNode`/
  `RestoreNode`/`RotateNodeKey` instead of calling `unix_now()`. **The code fix
  is real; `validate_linux_membership_revoke_applies` still does not exist**
  (zero hits in `vm_lab/mod.rs`) — this is Tier 0 priority 1 above. Until that
  stage exists and passes live, the fix's correctness rests on unit tests only.

### FINDING-B (CRITICAL) — DD-03 / RSA-0007/0008: dataplane/exit/LAN admission is revocation-blind

- **Where:** `crates/rustynetd/src/dataplane.rs:361` (`self.policy.evaluate(...)`),
  `crates/rustynetd/src/phase10.rs:4957` (`set_exit_node` / shared-exit) and
  `:5027` (LAN route grant) all call the membership-**blind** `evaluate`. Only
  `service_exposure.rs` (NAS/LLM) uses `evaluate_with_membership`.
- **Impact:** a peer that is **revoked** in signed membership but still named by
  a stale (or wildcard) allow rule keeps dataplane peer-admission, shared-exit,
  and LAN access — revocation does not cut live traffic on the main data paths.
  (The daemon's signed-bundle *provisioning* gate `check_peer_membership_active`
  at phase10.rs:4759 does re-check membership, which contains the worst case, but
  the per-decision ACL admission path does not.)
- **Proposed fix:** route the dataplane/exit/LAN ACL decisions through
  `evaluate_with_membership` (as service_exposure already does) so a revoked
  identity is denied regardless of a residual allow rule. Then the live
  `validate_linux_revoked_peer_denied_e2e` stage (audit DD-03) passes.
- **STATUS UPDATE (2026-07-01):** fix landed in `92e5748` ("phase10: gate
  exit-node + LAN-route ACLs with membership"). Verified present in current
  code: both `Phase10Controller::set_exit_node` and `ensure_lan_route_allowed`
  in `crates/rustynetd/src/phase10.rs` now call `evaluate_with_membership`; a
  repo-wide grep of `rustynetd` found no remaining production call to the
  membership-blind `evaluate()` (the sole hit, `policy_default_deny_audit.rs:198`,
  is the truth-table audit harness deliberately exercising both evaluators for
  comparison — not a live trust decision path). **The code fix is real;
  `validate_linux_revoked_peer_denied_e2e` still does not exist** (zero hits
  in `vm_lab/mod.rs`) — this is Tier 0 priority 2 above.

## 2.2) Other audit-surfaced defect candidates (need code verification before a stage can pass)

These confirmed-implementable stages bundle a product fix because the control is
not currently observable as fail-closed through the real surface (each is its own
finding until the fix lands — the stage is written to FAIL on today's code):

- **RSA-0037 / DOS-1** — relay `HelloLimiter` (`crates/rustynet-relay/src/transport.rs`)
  is `HashMap<String,(u32,Instant)>` with **no prune/cap** → unauthenticated
  remote memory-exhaustion (rate is capped per node_id but map *cardinality* is
  unbounded). Verified present. Fix: cap + prune mirroring `PreAuthHelloLimiter`.
- **RSA-0048 / DOS-2** — LLM gateway accepts TCP with **no read/write timeout** +
  no concurrent-connection cap → slowloris. Fix: `set_read_timeout`/`set_write_timeout`
  + an `AtomicUsize` accept cap.
- **RSA-0029 / RR-01-adjacent** — traversal `CoordinationReplayWindow`
  (`crates/rustynetd/src/traversal.rs`) is **in-memory only** (reset on daemon
  restart) → post-restart coordination-nonce replay within the 24h TTL. (Note:
  the per-bundle *fetcher* `WatermarkStore` IS disk-backed — RR-01 tests that
  path, which works; this is the separate traversal-nonce window.)
- **RSA-0034 / GM-1** — gossip ingest (`peer_gossip` / `GossipNode::ingest_inbound_bundle`)
  takes no membership argument and reads only `self.peers` → a revoked node can
  re-advertise and be re-admitted. Fix: thread membership status / prune revoked
  ids before ingest.
- **RSA-0014 / CPA-2** — `emit_role_audit` (`crates/rustynet-cli/src/main.rs`) is
  fail-open: a role transition proceeds even if the durable audit append fails,
  contradicting §6.D.6 "MUST emit". Fix: fail-closed audit append.

## 2.3) Implemented this phase (FAIL-LOUD, Skip-by-default, bite-tested)

| stage | surface / audit id | severity | status |
|---|---|---|---|
| `validate_linux_ipv6_leak` | killswitch_leak / (Linux IPv6) | high | ✅ committed (phase 1) |
| `validate_linux_privileged_helper_allowlist` | priv_helper / PH-1 | medium | ✅ committed (phase 1) |
| `validate_macos_ipv6_leak` | killswitch_leak / KL-4 (macOS half) | high | ✅ committed |
| `validate_linux_exit_demotion_residue` | exit_nat_residue / EXNAT-1 | high | ✅ committed |
| `validate_linux_membership_signature_forgery` | signature_forgery / SIGFORGE-1 (+2,3,4,7) | high | ✅ committed |
| `validate_linux_policy_default_deny` | default_deny / DD (truth table) | high | ✅ committed |

Each ships a daemon producer (or reuses an existing read-only snapshot), an
orchestrator validator, a `scripts/e2e/capture_*.sh` wrapper or in-binary audit,
run-matrix accounting, and tampered-input bite unit tests proving the validator
fails when the defence is absent. All gates green; default/dry runs Skip cleanly.

A self-review pass (6 skeptic agents) hardened these: the privileged-helper
audit now accepts the orchestrator's always-appended `--no-fail-on-drift` (it was
dead-on-arrival), the nft v6-containment detector only credits drops on egress
base chains, and both IPv6 stages now carry a `probe_attempted` gate so a
never-run probe is inconclusive-fail rather than a vacuous pass.

The signature-forgery stage (`rustynetd membership-signature-audit`) drives the
REAL `apply_signed_update`/`decode_signed_update` funnel with an 11-case forgery
battery + a must-accept valid baseline, including the **malleable non-canonical
S** case (`S' = S + ℓ`) — the RN-22 / Nebula-CRL-bypass defense. How to run live:
`cargo run -p rustynet-cli -- ops vm-lab-validate-linux-security --linux-vm
<alias> --ssh-identity-file <id> --report-dir <dir>` → stages
`validate_linux_membership_signature_forgery` + `validate_linux_privileged_helper_allowlist`
run the shipped daemon's in-binary audits over the public CLI (no artifact needed).

## 2.4) Full confirmed-implementable backlog (111 gaps, by surface)

The complete prioritized backlog from the audit. ✅DONE marks the four landed
this branch. Everything else is a ready-to-implement spec (the audit result has
the full daemon-module / validator-contract / bite-test for each). Critical/high
first within each surface.

#### default_deny  (4)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| critical | medium | DD-03 | validate_linux_revoked_peer_denied_e2e (+ macos/… | Revocation-aware default-deny end-to-end: a REVOKED node must be denied at dataplane peer-… |
| high | medium | DD-02 | validate_linux_empty_policy_revokes_reachability… | Default-deny under POLICY MUTATION: pushing an EMPTY signed assignment bundle to a RUNNING… |
| high | medium | DD-05 | validate_linux_malformed_bundle_failclosed | Malformed-bundle fail-closed: a signed-but-malformed bundle (bad CIDR, truncated, bad sche… |
| medium | medium | DD-06 | validate_linux_service_context_default_deny (+ m… | Service-context default-deny end-to-end (NAS/LLM): empty/missing TrafficContext and a lega… |

#### role_transition  (6)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| critical | medium | RT-1 | validate_linux_unsigned_capability_elevation_den… | SecMinBar §6.D.3 — capability changes require owner signature; local-only acceptance of ca… |
| high | small | RT-2 | validate_linux_blind_exit_reversal_denied | SecMinBar §6.D.2 — BlindExit irreversibility: a blind_exit node MUST refuse every other-ro… |
| high | small | RT-3 | validate_linux_exit_revoke_teardown_ordering | SecMinBar §6.D.7 — exit-serving NAT/forwarding MUST be torn down BEFORE serves_exit is rem… |
| medium | medium | RT-5 | validate_linux_role_audit_tamper_detected | SecMinBar §6.D.6 — tamper-evident transition audit: every transition emits an append-only … |
| medium | medium | RT-6 | validate_linux_relay_deploy_failure_aborts_trans… | SecMinBar §6.D.4/§6.D.5 — service deploy precedes capability advertisement; failure to dep… |
| low | medium | RT-8 | validate_linux_concurrent_role_transition_resolu… | SecMinBar §6.D.1 — concurrent/racing role transitions resolve fail-closed (one outcome win… |

#### signature_forgery  (7)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | SIGFORGE-1 | validate_linux_signed_bundle_forgery --bundle-ty… | SecMinBar §3.2 (signed control/trust data validated before application) + §6.B (trust anch… |
| high | small | SIGFORGE-7 | Covered as the malleable_S attack_class WITHIN v… | RN-22 / SecMinBar §3 one-hardened-path: ed25519 signature malleability (verify_strict, not… |
| medium | small | SIGFORGE-2 | validate_linux_signed_bundle_forgery --bundle-ty… | SecMinBar §3.8 (signed endpoint-hint/traversal bundle authenticated, replay-protected, fre… |
| medium | small | SIGFORGE-3 | validate_linux_signed_bundle_forgery --bundle-ty… | SecMinBar §6.B (DNS-zone bundle verified against trust anchor): forged dns-zone bundle rej… |
| medium | small | SIGFORGE-4 | validate_linux_signed_bundle_forgery --bundle-ty… | SecMinBar §6.B / gossip trust (signed peer-gossip bundle verified): forged peer-gossip bun… |
| medium | medium | SIGFORGE-5 | validate_linux_signed_bundle_forgery --bundle-ty… | SecMinBar §3.8 (traversal/relay) + §4.7 (relay abuse controls): forged relay-session-token… |
| medium | medium | SIGFORGE-6 | validate_linux_signed_bundle_forgery --bundle-ty… | SecMinBar §3.2 (signed control data validated before application): forged assignment bundl… |

#### replay_rollback  (6)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | RR-01 | validate_linux_replay_persistence | Cross-reboot persistence of the trust/traversal/assignment/dns-zone anti-replay watermark … |
| medium | medium | RR-02 | validate_linux_traversal_coord_replay_persistenc… | Traversal coordination replay window — daemon.rs traversal_coordination_replay_window (Coo… |
| medium | medium | RR-03 | validate_linux_enrollment_replay_persistence | Enrollment token single-use ledger durability across reboot — enrollment_consume.rs writes… |
| medium | large | RR-06 | validate_macos_replay_persistence / validate_win… | IPv6/cross-OS parity of cross-reboot replay-persistence (macOS LaunchDaemon restart via la… |
| medium | large | RR-07 | implement the live body of chaos_clock_jump_back… | Live adversarial clock-rollback driving the persisted watermark window (the in-tree chaos_… |
| low | small | RR-04 | fold into validate_linux_replay_persistence (bun… | Membership epoch-chain monotonicity + MembershipReplayCache (membership.rs apply_signed_up… |

#### fail_closed_failure  (5)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | large | FCF-1 | validate_linux_crash_midapply_failclosed. New re… | SecMinBar §3.4/§4: crash mid-apply of verified-but-not-yet-applied trust/membership state … |
| high | medium | FCF-2 | validate_linux_corrupt_state_failclosed. linux-m… | SecMinBar §3.4/§4, CLAUDE.md §10.1: corrupt/truncated/deleted persisted signed-state (trus… |
| medium | medium | FCF-3 | validate_linux_keystore_unavailable_failclosed. … | SecMinBar §4 key custody / §3.4: keystore unreachable/locked (encrypted-at-rest key/passph… |
| medium | medium | FCF-4 | validate_linux_replay_persistence. New read-only… | SecMinBar §3.3/§4: anti-replay/rollback protection must PERSIST across daemon restart/rebo… |
| medium | large | FCF-7 | validate_macos_corrupt_state_failclosed and vali… | Cross-OS parity (CrossPlatformRoleParityPlan): crash-midapply / corrupt-state / keystore-u… |

#### killswitch_leak  (5)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | KL-2 | validate_macos_killswitch_leak | macOS pf killswitch cleartext IPv4 leak — real egress capture (parity with Linux no-leak g… |
| high | large | KL-3 | validate_windows_killswitch_leak | Windows WFP killswitch cleartext IPv4 leak — real egress capture (parity with Linux no-lea… |
| high | medium | KL-4 | validate_macos_ipv6_leak and validate_windows_ip… ✅DONE | IPv6 killswitch leak parity on macOS / Windows (IPv4-only killswitch lets native IPv6 bypa… |
| high | large | KL-5 | validate_linux_killswitch_routeflip_race (then m… | Route-flip RACE leak during tunnel bring-up / tear-down (per OS) |
| medium | large | KL-6 | validate_linux_killswitch_midhandshake_leak (con… | Leak during the mid-handshake window (tunnel iface + route up but WireGuard handshake not … |

#### dns_leak  (4)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | large | DNS-3 | validate_linux_dns_resolver_tamper (+ macos/wind… | DNS resolver config must stay fail-closed under mid-run tamper: daemon must re-assert loop… |
| high | medium | DNS-5 | validate_macos_dns_scutil_posture (extends/super… | macOS DNS fail-closed must inspect the authoritative resolver layer (SystemConfiguration /… |
| medium | medium | DNS-2 | validate_linux_dns_aaaa_leak (+ validate_macos_d… | DNS fail-closed must contain AAAA/IPv6 lookups, not just A records (SecMinBar 3.8/6; IPv6 … |
| medium | large | DNS-4 | validate_linux_doh_dot_bypass (+ macos/windows s… | Encrypted-DNS bypass containment: in protected mode DoH (TCP/443 to a known DoH endpoint) … |

#### relay_plaintext  (4)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | RPT-01 | validate_linux_relay_ciphertext_only | Relay-sees-only-ciphertext: relay forwards opaque WireGuard datagrams byte-for-byte, never… |
| high | medium | RPT-02 | validate_linux_relay_token_attack | Relay session-token unforgeability + anti-replay + scope/relay-binding enforced on the LIV… |
| medium | large | RPT-03 | validate_linux_relay_mitm_resistance | Relay-MITM resistance proven empirically: relay cannot MITM a two-hop session (no peer key… |
| medium | large | RPT-04 | validate_macos_relay_ciphertext_only / validate_… | Per-OS parity for relay-ciphertext + token-attack assurance on macOS and Windows relays (C… |

#### exit_nat_residue  (5)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | EXNAT-1 | validate_linux_exit_demotion_residue — on a live… ✅DONE | SecMinBar §6.D.7 — exit-serving NAT must be torn down (forwarding + masquerade) on serves_… |
| high | medium | EXNAT-3 | validate_linux_exit_crash_residue — on a live Li… | SecMinBar §3.4/§4 (fail-closed) + §6.D.7 (residue) — after an ungraceful exit (SIGKILL/cra… |
| high | medium | EXNAT-4 | validate_macos_exit_demotion_residue — serving s… | SecMinBar §6.D.7 demotion residue parity on macOS — teardown flushes the com.rustynet/nat … |
| medium | small | EXNAT-2 | Tighten evaluate_{linux,macos,windows}_exit_nat_… | SecMinBar §6.D.7 (residue) + §8 (IPv6 leak prevention) — exit NAT teardown must restore IP… |
| medium | medium | EXNAT-5 | validate_windows_exit_demotion_residue — snapsho… | SecMinBar §6.D.7 demotion residue parity on Windows (WinNAT MSFT_NetNat + per-interface Fo… |

#### priv_helper  (8)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | PH-2 | validate_linux_privileged_helper_socket_fuzz (ne… | Live helper SOCKET frame hardening against a RUNNING helper: magic/version/type/length-bou… |
| high | medium | PH-3 | validate_linux_privileged_helper_peer_authz (ext… | Live cross-uid peer rejection: helper accept-time peer_uid==allowed_uid||0 (privileged_hel… |
| high | medium | PH-4 | validate_linux_privileged_helper_socket_perms (n… | Live helper socket filesystem security: owner-only / root-managed-shared perms — refuse sy… |
| high | medium | PH-5 | validate_linux_privileged_helper_binary_integrit… | Live helper BINARY integrity: privileged programs resolved only from absolute, root-owned,… |
| high | medium | PH-7 | validate_macos_privileged_helper_allowlist (reus… | macOS privileged-helper parity: pfctl argv allowlist (anchor-name escape, path traversal, … |
| medium | large | PH-6 | validate_linux_privileged_helper_kill_scope — GA… | kill helper command scope: validate_kill_args (privileged_helper.rs:1853) only permits -TE… |
| medium | small | PH-8 | validate_windows_privileged_helper_blocked (new … | Windows privileged-helper remains BLOCKED through the public surface: named-pipe helper IP… |
| medium | small | PH-9 | folded into validate_linux_privileged_helper_soc… | Single-threaded helper accept-loop DoS resistance: a slow-loris partial frame must not wed… |

#### enrollment_token  (2)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | ENR-1 | validate_linux_enrollment_replay | Single-use enrollment token (SecMinBar §6.C.3 + §3.3 anti-replay): a consumed token MUST b… |
| medium | medium | ENR-3 | validate_linux_enrollment_freshness | SecMinBar §6.C.3 freshness + §3.3: expired and future-issue (clock-skew) tokens MUST be re… |

#### gossip_membership  (2)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | GM-1 | validate_linux_gossip_revoked_readmit | SecurityMinimumBar 6.B/6.C.1 membership revocation enforced before trust-sensitive gossip … |
| medium | medium | GM-2 | validate_linux_gossip_ingest_flood_bound | SecurityMinimumBar 4 (resource exhaustion / High) + 6.B unbounded trust-state growth: per-… |

#### key_custody  (6)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | KC-02 | validate_macos_key_custody in run_macos_orchestr… | SecMinBar §4 + CrossPlatformRoleParity — macOS key custody must be FAIL-LOUD orchestrator-… |
| high | medium | KC-04 | live_windows_key_custody_test standalone bin (pa… | SecMinBar §4 + §6.C.4 — Windows MUST reject a world-readable KEY FILE at startup (RSA-0002… |
| medium | medium | KC-03 | live_macos_key_custody_test standalone bin (pari… | SecMinBar §4 — startup MUST reject too-broad key permissions on macOS at parity with Linux… |
| medium | large | KC-05 | validate_linux_secret_memory_hygiene producer: r… | SecMinBar §4 'Never log secrets/private key material' — runtime key material MUST NOT leak… |
| medium | small | KC-06 | Extend Windows + macOS collectors to include the… | SecMinBar §4 + §6.C.4 — Ed25519 OWNER/MEMBERSHIP signing-key passphrase custody must be OS… |
| medium | medium | KC-07 | live_macos_secrets_not_in_logs_test + live_windo… | SecMinBar §4 'Never log secrets' — macOS and Windows runtime logs MUST NOT contain key mat… |

#### mitm_handshake  (4)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | MITM-1 | validate_macos_endpoint_hijack — vm_lab stage_ou… | Endpoint hijack rejection on macOS (SecMinBar §3.2/§3.8): attacker-rewritten peer endpoint… |
| high | medium | MITM-2 | validate_windows_endpoint_hijack — vm_lab stage … | Endpoint hijack rejection on Windows (SecMinBar §3.2/§3.8): tampering C:\ProgramData\Rusty… |
| high | medium | MITM-3 | validate_linux_traversal_hint_injection — true l… | Forged / wrong-signer / stale / replayed signed traversal coordination record (endpoint-hi… |
| medium | large | MITM-4 | validate_linux_stun_candidate_spoof — live stage… | Spoofed STUN-mapped endpoint candidate must not be gossiped as a reachable peer endpoint (… |

#### toctou_races  (3)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | TOCTOU-1 | validate_linux_enrollment_concurrent_consume — L… | Enrollment single-use ledger atomicity under concurrency (SecurityMinimumBar §3.3 line 26 … |
| high | medium | TOCTOU-2 | validate_linux_concurrent_membership_apply — Lin… | Deterministic signed-membership mutation under concurrency (SecurityMinimumBar §3 one-hard… |
| medium | large | TOCTOU-3 | validate_linux_crash_mid_membership_apply — repl… | Crash mid-transition atomicity / fail-closed recovery (SecurityMinimumBar §3.4 fail-closed… |

#### dos_resource  (2)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | large | DOS-1 | validate_linux_relay_hello_node_id_flood | Relay per-node_id HelloLimiter map must be bounded/pruned (SecMinBar §4 High relay abuse/c… |
| high | large | DOS-2 | validate_linux_llm_gateway_slowloris | LLM gateway connection must enforce read/write timeouts and a concurrent-connection bound … |

#### crossnet_traversal  (4)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | large | CNT-1 | validate_linux_upnp_ssrf — orchestrator stage ga… | uPnP IGD SSDP LOCATION/controlURL SSRF (AUDIT-051 / RSA-0035). SecMinBar §3.7 strict input… |
| high | medium | CNT-2 | validate_linux_candidate_injection — orchestrato… | Remote candidate injection forcing unintended direct path / policy bypass. SecMinBar §3.8 … |
| medium | large | CNT-3 | validate_linux_relay_only_no_leak — orchestrator… | Relay-only path under hostile (symmetric/hard) NAT must not leak underlay traffic and rela… |
| medium | large | CNT-4 | validate_linux_failback_acl_bite — orchestrator … | Failover/failback transition cannot bypass ACL/trust/leak controls. SecMinBar §3.8 leak, §… |

#### control_plane_audit_supply  (3)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | CPA-1 | validate_linux_audit_chain_integrity (mirror mac… ⚠️UNVERIFIED (was ✅DONE) | SecMinBar §3.9 — tamper-evident, append-only audit log with active integrity verification.… **2026-07-01: grepped `vm_lab/mod.rs` + `src/bin/` for `audit_chain_integrity` — zero hits. Either a standalone script exists outside those paths, or this marker is wrong. Confirm before trusting; see priority-order section above.** |
| high | medium | CPA-2 | validate_linux_audit_failclosed. Render audit pa… | SecMinBar §3.9 + §6.D.6 (every role transition — success/fail/abort — MUST emit an append-… |
| medium | medium | CPA-3 | validate_linux_control_tls_posture_failclosed. N… | SecMinBar §3.2 — TLS 1.3 enforced for control-plane (attested signed posture, not a wire h… |

#### secminbar_sweep  (16)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | S3-5 | validate_windows_host_boundary (wire existing wi… | §3.5 Host-OS boundary enforcement (block Linux-only provisioning on non-Linux; never creat… |
| high | medium | S3-9 | validate_linux_audit_integrity | §3.9 Audit/forensics (tamper-evident append-only hash-chain audit log; retention + integri… |
| high | medium | S6B-1 | validate_linux_trust_anchor_custody (+ validate_… | §6.B Bootstrap trust anchor — daemon refuses to start until membership.owner.key.pub prese… |
| high | small | S6D-9 | validate_windows_platform_blocked_role (+ valida… | §6.D.9 Platform-blocked roles fail closed (non-client roles on Windows, blind_exit on macO… |
| high | large | S6E-1 | validate_linux_nas_tunnel_only_bind (+ validate_… | §6.E E1 Service endpoint binds tunnel-only (nas/llm API binds mesh tunnel addr only; non-t… |
| high | large | S6E-2 | validate_linux_service_default_deny | §6.E E2 Default-deny per-peer service authorisation (every nas/llm session gated; empty/mi… |
| high | large | S6E-3 | validate_linux_service_revocation_teardown | §6.E E3 Service teardown precedes capability revocation (on serves_nas/serves_llm removal:… |
| high | large | S6E-4 | validate_linux_service_token_revocation | §6.E E4 App-layer token cannot exceed signed policy (session token re-checked vs CURRENT s… |
| medium | medium | S3-3 | validate_linux_enrollment_rate_limit | §3.3 Auth/enrollment hardening (per-IP/per-identity rate limit, lockout/backoff, anti-repl… |
| medium | medium | S4-7 | validate_linux_relay_flood_bound (coverage-doc G… | §4.7 High — Relay abuse/capacity controls under load + reconnect churn (RSA-0037: per-node… |
| medium | medium | S6C-2 | validate_linux_anchor_bundle_pull_lan_refused | §6.C.2 Anchor bundle-pull default-deny (loopback bind 127.0.0.1:51822 by default; non-loop… |
| medium | medium | S6C-4 | validate_linux_anchor_secret_custody (+ macos/wi… | §6.C.4 Anchor secret custody (HMAC secret in OS-secure custody; plaintext rejected; Win DP… |
| medium | medium | S6C-5 | validate_linux_replay_persistence (coverage-doc … | §6.C.5 Anchor downgrade fail-closed (lower/equal-epoch bundle stripping anchor caps reject… |
| medium | medium | S6D-4 | validate_linux_relay_deploy_abort | §6.D.4 Service deploy precedes capability advertisement (deploy+verify rustynet-relay BEFO… |
| medium | medium | S6D-5 | validate_linux_relay_undeploy_abort | §6.D.5 Service undeploy precedes capability revocation (stop+remove relay BEFORE revocatio… |
| low | small | S3-10 | validate_macos_codesign | §3.10 Supply-chain integrity (signed artifacts, SBOM, staged tracks) |

#### rsa_open_findings  (15)

| sev | eff | id | proposed stage | control |
|---|---|---|---|---|
| high | medium | RSA-0009 | validate_linux_membership_revoke_applies (+macos… | Membership revocation + key rotation must apply via the signed-update path (SecMinBar §3.3… |
| high | medium | RSA-0063 | validate_macos_bootstrap_privesc_residue + stati… | Privilege boundary / fail-closed on bootstrap error (SecMinBar §3.7). macOS bootstrap must… |
| medium | small | RSA-0031 | PRIMARY: unit test + schema/validator extension … | Exit-NAT teardown verification must fail closed (SecMinBar §6.D ctrl 7 — NAT residue after… |
| medium | medium | RSA-0037 | PRIMARY unit bite (no VM). OPTIONAL live validat… | Relay abuse/capacity controls under churn (SecMinBar §4.7; CWE-770). Relay must bound memo… |
| medium | medium | RSA-0023 | PRIMARY: §6-mandated concurrent-consume integrat… | One-time enrollment credential consumption must be atomic/race-safe (SecMinBar §6.C ctrl 3… |
| medium | small | RSA-0007 | PRIMARY regression unit in rustynetd phase10: re… | Default-deny / revocation enforcement on dataplane ACL gates; one hardened path (SecMinBar… |
| medium | medium | RSA-0046 | No live stage. Regression unit + a security_regr… | Argv-only privileged exec; no untrusted shell construction (SecMinBar §3.7; CWE-78). |
| medium | small | RSA-0047 | No live stage. Regression unit: replace .lines()… | Bounded input on agent-facing services (SecMinBar §6; CWE-770). |
| medium | small | RSA-0059 | No live stage. Regression unit over the script-b… | No untrusted shell construction in orchestrator (SecMinBar §3.7; CWE-78). |
| medium | medium | RSA-0064 | No live stage. Add a supply_chain_integrity_gate… | Supply-chain integrity of bootstrap dependencies (SecMinBar §10; CWE-494). |
| medium | medium | RSA-0025 | Windows regression test + optional extension to … | Encrypted-at-rest key custody with strict permissions on Windows (SecMinBar §3.4/§5; CWE-7… |
| low | small | RSA-0033 | PRIMARY unit regression. Live: extend the existi… ✅DONE | Privileged-helper least privilege (SecMinBar §3.7; CWE-250). Root helper's kill builtin mu… |
| low | medium | RSA-0008 | Regression unit ONLY (no live stage). Give Contr… | Membership-gated signed-artifact issuance (SecMinBar §3.6/§3.2; CWE-863). |
| low | medium | RSA-0080 | No live stage. Owner decision: define a real sec… | Secret hygiene / secure deletion of key material + mandatory gate must pass (SecMinBar §4;… |
| info | small | RSA-0011 | Regression unit only (no live stage at Info). Pe… | Anti-rollback floor on MAC-protected TrustState (SecMinBar §3.2/§3.3; CWE-294). |

### Backdoor/infeasible findings (NOT auto-implementable)

- **role_transition/RT-7** (infeasible): SecMinBar §6.D.8 — mobile role lock: iOS/Android FFI MUST refuse any role set != client and advertise client-only on snapshot reload.
- **enrollment_token/ENR-4** (infeasible): SecMinBar §6.C.3 token scope / target-node binding ('over-scoped token', 'token used on WRONG node'): a token should not be redeemable beyon…
- **dos_resource/DOS-4** (infeasible): MCP server stdin line reader must bound per-line length so a newline-less line cannot exhaust memory (RSA-0047).

---

# Phase 3 — Prioritization, verification, and stage-onboarding mechanics (2026-07-01)

A cross-cutting review answered: what's the build order across everything above,
are the "done" claims still true, and — since ~15 new stages are queued —
what has to change in the orchestrator, both MCP servers, and the lab-monitor
GUI to onboard them efficiently. The priority order itself, the FINDING-A/
FINDING-B fix-landed verification, the relay-forwarding correction, and the
CPA-1 flag are already folded into the top of this document (see "Priority
order" section) and inline into §2.1/§3/§2.4 rather than duplicated here. This
section is the supporting mechanics.

## 9) Stage-onboarding mechanics — orchestrator, MCP, GUI

There is **no single canonical stage registry**. Adding one new stage touches
up to four independent, hand-maintained places, and nothing enforces they stay
in sync:

1. **Orchestrator (`rustynet-cli`, source of truth)** — implement the stage,
   register it in the orchestrator's sequence in `crates/rustynet-cli/src/vm_lab/mod.rs`,
   have it write a row to `state/stages.tsv` under a specific name string.
2. **`rustynet-mcp-deepseek` (`crates/rustynet-mcp/src/bin/deepseek.rs`)** — only
   needed if the stage should be selectable as a role-platform cell:
   - Extend the `deepseek_lab_run` input schema (around line 5048-5057) and
     `build_orchestrator_args` (around line 4147-4243, mirror the existing
     `--<role>-platform` push pattern at lines 4198-4211).
   - If it deserves a canonical shortcut key, add a branch to `target_from_key`
     (lines 1184-1270).
   - To make it auto-selectable when it fails, extend the substring heuristic
     in `key_for_stage_or_cell` (lines 3978-4012) — it matches on
     `n.contains("macos")`/`n.contains("windows")` + a role keyword, not a
     structured lookup. **Practical convention: name new stages so they
     contain the OS + role keyword** (e.g. `validate_macos_privileged_helper_allowlist`)
     so autonomous failure-routing picks them up for free, with zero extra code.
3. **`rustynet-mcp-lab-state` (`crates/rustynet-mcp/src/bin/lab_state.rs`)** —
   add an entry to the static `STAGE_INFO` array (lines 4032-4237) so
   `explain_stage` describes the new stage instead of falling into "Unknown
   stage" (lines 4275-4285). Read-only/descriptive, no functional gating.
4. **`rustynet-mcp-repo-context` (`crates/rustynet-mcp/src/bin/repo_context.rs`)** —
   add a row to the hardcoded `ORCHESTRATOR_STAGES` markdown table constant
   (lines 2061-2094), returned verbatim by `get_orchestrator_stages`. Also a
   static string literal, not derived from code.

Polling tools need **zero changes** for a new stage — `deepseek_live_lab_result`,
`get_stage_log`, `get_run_matrix`, and `grep_report` are all generic tsv/csv/log
readers that pick up any new stage name automatically once the orchestrator
writes rows for it.

**No per-stage isolation exists for live-validation/adversarial stages.** Only
*setup* stages (`preflight`, `bootstrap_hosts`, `membership_setup`, etc. — the
full list is `setup_stage_names()` in `vm_lab/mod.rs:2207-2227`) support
`--rerun-stage`/`--resume-from` via `start_live_lab_run`. For a test stage
(traffic, role_switch, exit_handoff, relay, anchor, the new adversarial stages
above), the closest approximation is `rebuild_nodes` + `skip_soak`, which still
replays the *entire* live suite rather than isolating one stage. Given ~15
new adversarial stages are queued above, each needing the same iterate-fix-
reverify cycle the Windows anchor stage needed this session, **building a
lightweight per-stage isolation mechanism for test stages (not just setup
stages) is the single highest-leverage infra investment before starting Tier 1**.

**Dead config found, not wired to either MCP server:** `disabled_stages` exists
in the lab-monitor GUI's own config (`crates/rustynet-lab-monitor/src/config.rs`,
`app.rs`, `ui/config_panel.rs`) but has no effect on `deepseek_lab_run` or
`start_live_lab_run` — the control looks functional in the GUI but does
nothing. Either wire it up for real or remove it before it misleads whoever's
watching the monitor.

## 10) GUI representation — `rustynet-lab-monitor` `run_matrix.rs`

Adding a new stage to the FULL STAGE MATRIX tab:

- **Generic stage, applies uniformly to all 3 OSes**: add the suffix string to
  `GENERIC_STAGE_ORDER` (`crates/rustynet-lab-monitor/src/data/run_matrix.rs:410-432`).
  Everything else (`load_full_stage_matrix`, the header-bar counter) derives
  automatically. Bump the two hardcoded test totals (`21` → `21+N`,
  `78` → `78+N` in `full_stage_matrix_has_21_generic_stages_per_os_in_canonical_order`
  and `stage_progress_agrees_with_full_stage_matrix_total_on_a_complete_csv`).
- **Single-OS one-off security column**: add to `MACOS_ONEOFF_COLUMNS` /
  `WINDOWS_ONEOFF_COLUMNS` (lines 436-443) — same auto-derivation. There is
  **no `LINUX_ONEOFF_COLUMNS` list today**; several Tier-1 stages above
  (bootstrap privesc residue, Linux-specific key custody) are Linux-only
  security checks with nowhere to go in the current schema — create that list
  (mirroring lines 436-443) before those land, not after.
- **No functional-vs-security category exists.** `StageMatrixEntry` has no
  category/kind field — every stage in `GENERIC_STAGE_ORDER` and both one-off
  lists renders identically in the FULL STAGE MATRIX tab today. Given this
  document's whole purpose is closing security gaps, tag stages now: add a
  `StageCategory::{Functional, Security}` field to `StageMatrixEntry`,
  retroactively tag the existing security-flavored entries (`key_custody`,
  `secrets_not_in_logs`, all 4 one-off columns), and the GUI can grow a
  visually distinct SECURITY section immediately — each of the ~15 Tier-1
  stages above then just needs a tag, not a structural change, when it lands.

## 11) Verification ledger for this phase (what was checked against real code, not taken on a report's word)

| Claim | Verified how | Result |
|---|---|---|
| FINDING-A (RSA-0009) fixed | Read current `membership.rs::reduce_membership_state`, confirmed `op_created_at_unix` param + usage on all 4 mutation ops | Confirmed fixed, `a23df5f` present in HEAD history |
| FINDING-B (DD-03/RSA-0007) fixed | Grepped `rustynetd` for `.evaluate(` vs `.evaluate_with_membership(`, read `phase10.rs` call sites | Confirmed fixed, `92e5748` present in HEAD history; sole remaining blind-`evaluate` call is the audit harness itself |
| `validate_linux_membership_revoke_applies` / `validate_linux_revoked_peer_denied_e2e` exist | Grepped `crates/rustynet-cli/src/` + `documents/` | Zero hits outside this document — neither stage is built |
| Relay forwarding is live-proven ("✅" in §3 row 8) | Read `live_linux_relay_test.rs` (lifecycle/healthz only) and `live_linux_two_hop_test.rs` (separate exit-chaining subsystem) | Claim was inaccurate — corrected in §3; cross-referenced against `LiveLabCoverageAndHonestyAudit_2026-06-25.md` findings #7/#8 and `MasterWorkPlan_2026-03-22.md` HP-3 |
| CPA-1 (`validate_linux_audit_chain_integrity`) is ✅DONE | Grepped `vm_lab/mod.rs` + `src/bin/` for `audit_chain_integrity` | Zero hits — flagged ⚠️UNVERIFIED in §2.4, not re-asserted as done |
