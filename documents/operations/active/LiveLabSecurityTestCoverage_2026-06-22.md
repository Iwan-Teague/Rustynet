# Live-Lab Security Test Coverage & Threat Matrix — 2026-06-22

Status: **active**. Owner track: security test engineering. Branch:
`claude/livelab-security-tests`.

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
| 8 | Relay-sees-plaintext | §3 (relay), Dataplane plan | `live_linux_two_hop_test.sh`, relay membership-binding gate; relay zero-copy forward unit | — | ✅ forwarding; 🧪 explicit "relay cannot decrypt" assertion is structural |
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
