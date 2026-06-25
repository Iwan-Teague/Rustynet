# Live-Lab Coverage & Capture-Honesty Audit — 2026-06-25

Status: **AUDIT / PLAN (no code changes in this pass)**. Read-only research across
the whole live-lab surface (5 parallel audit tracks + external best-practice
research). Author: Iwan-Teague.

Purpose: answer "are we *thoroughly* stress-testing Rustynet in the live lab, on
**all three OSes for every role and exploitable surface**, and is the captured
evidence *honest*?" — so that "passed the live lab ⇒ deployable" is a true
statement. This doc is the gap map + the prioritized plan we execute next.

---

## 0. Executive summary (the headline findings)

1. **Linux is deeply tested; macOS and Windows are shallow.** macOS has exactly
   **one** dedicated live Rust test binary (`live_macos_anchor_test.rs`); Windows
   has **zero**. Real, equivalent cross-OS parity exists on only **2** functional
   areas (relay lifecycle, mixed-topology). Everything else either degenerates,
   runs a *different/narrower* validator, or fails closed as "not enabled on this
   OS yet."
2. **Every adversarial / exploit-path surface is Linux-only.** Endpoint hijack,
   server-IP bypass, rogue-path, enrollment-token replay, gossip/membership
   poisoning, STUN/ICE traversal adversarial, signed-state forgery/replay — all
   tested on Linux, **untested on macOS and Windows**. An attacker on a mac/win
   node attacks unproven defenses.
3. **The "reference" OS isn't even clean.** The capture-honesty pass I did last
   session fixed macOS/Windows but **left Linux with the same defects**: a
   **fail-open** exit-NAT teardown (an `nft`/`/proc` read error reads as "torn
   down" — a false clean-teardown on the release-blocking open-relay path) and a
   **vacuous** DNS-leak proof (passes on an empty pcap with no active probe).
4. **The `exit-handoff` "pass" on mac/win is deceptive false-parity** — it runs a
   single-exit NAT setup/teardown check, **0 of the 6 Linux failover checks**.
   Green status masks zero handoff coverage.
5. **Three chaos tests are inert scaffolds on *all* OSes** — `clock_attack`,
   `crash_recovery`, `resource_exhaustion` emit `status:fail "not enabled by this
   scaffold slice"` and never touch a host. Clock-skew and crash-recovery are
   unproven everywhere.
6. **nas and llm service-hosting roles have ZERO live coverage on any OS.**
7. ~~**macOS has dead capability:** `macos_runtime_acls.rs` / `macos_key_custody.rs`
   producers never run.~~ **CORRECTED 2026-06-25 (Wave 2-B recon):** this audit
   finding was WRONG. The macOS adapter's `run_validator` (`adapter/macos.rs:163-167`)
   instantiates `MacosDaemonProbe` and runs `macos-runtime-acls-check` /
   `macos-key-custody-check` via `sudo -n`, and `ValidateBaselineRuntime`
   (`stage/validate_runtime.rs:30-48`) drives every op (RuntimeAcls, KeyCustody, …)
   through it. So the macOS ACL + key-custody producers ARE invoked live in the
   rust-native pipeline. The only dead code is the unused standalone
   `daemon_probe_for` *helper* (`mod.rs:6296`, `#[allow(dead_code)]`) — harmless
   scaffolding, not a coverage gap.

Net: the live lab today proves "Linux works and is hard to break"; it does **not**
prove the cross-platform mandate (`CrossPlatformRoleParityPlan_2026-06-21.md`: "no
OS may be a capability limiter").

---

## 1. Architecture: there are two orchestrators + a standalone test layer

- **Rust-native `StageId` pipeline** (`orchestrator/`), selected when `--node
  <alias>:<role>` flags are present (`vm_lab/mod.rs:6931`). All three OSes run
  through it uniformly via the `NodeAdapter` trait (`adapter/node_adapter.rs:53`,
  factory `adapter/factory.rs:35`). Per-OS behavior lives in `adapter/{linux,
  macos,windows}.rs`. Bring-up, membership/bundle distribution, baseline
  validation, traffic, and tunnel checks are **genuinely cross-OS** here.
- **Legacy bash + bolt-on path** (no `--node`): Linux via the bash live-lab
  script; macOS via `run_macos_orchestration_stages` (`mod.rs:8169`), Windows via
  `run_windows_orchestration_*` (`mod.rs:7722,11240`). Flag-elected, dry-run-aware.
- **Standalone deep tests**: `crates/rustynet-cli/src/bin/live_*.rs` (27 Rust
  binaries) + `scripts/e2e/*.sh` wrappers + daemon-side producers
  (`crates/rustynetd/src/*_capture/_snapshot/_failclosed/_lifecycle`) + validators
  (`vm_lab/mod.rs` `evaluate_*`/`validate_*`). This is where the depth lives — and
  where the Linux-vs-mac/win asymmetry is starkest.

The mac/win shell wrappers (`live_{macos,windows}_*.sh`) are mostly one-liners:
`exec cargo run --bin live_linux_<x>_test -- --platform {macos|windows}`. Four of
those shared binaries **fail closed** on non-Linux via
`enforce_linux_only_until_validator_lands` (`bin/live_lab_*support/mod.rs`):
`lan_toggle`, `managed_dns`, `role_switch_matrix`, `two_hop`. Their mac/win green
is honest-but-empty (a loud fail recorded), not coverage.

---

## 2. Coverage Matrix A — roles / functional areas × OS

Legend: ✅ real & equivalent · 🟡 real but narrower/host-only/partial · 🟥
no-op/hard-fail/missing · ⬛ degenerate-failclosed in integrated pipeline.

| Functional area | Linux | macOS | Windows | Note |
|---|---|---|---|---|
| Bring-up / install / membership / bundle distribution / traffic / tunnel check (integrated pipeline) | ✅ | ✅ | ✅ | adapter-uniform; genuinely cross-OS |
| anchor (membership/gossip/enrollment/downgrade) | ✅ (6 substages) | 🟡 ~5–6 real | 🟡 ~4 real (gossip+downgrade skipped) | `live_linux_anchor_test.rs` shared via RemoteShellHost |
| anchor bundle-pull (A1.2) | ✅ | ✅ dedicated `live_macos_anchor_test.rs` | 🟥 none dedicated | only macOS Rust binary |
| anchor bundle-pull **runtime** (integrated stage) | ✅ | ⬛ reported-skip | ⬛ reported-skip | `role.rs:61` Anchor=Linux-only gate |
| relay lifecycle | ✅ (7) | ✅ 7/7 | ✅ 7/7 | **genuine parity** (RemoteShellHost) |
| relay deploy+validation (integrated stage) | ✅ | ✅ | ⬛ reported-skip | `role_validation/relay.rs:70` |
| **relay data-plane** (frame client→relay→peer, zero-ingress, ciphertext-only) | 🟡 contract/dry-run only | 🟡 | 🟡 | **no OS proves a forwarded frame** (capture finding #7) |
| exit / **exit-handoff failover** | ✅ (6 failover checks) | 🟥 wrong validator (0/6) | 🟥 wrong validator (0/6) | mac/win run a NAT-lifecycle check, **not** failover — deceptive green |
| exit active-NAT egress (integrated ActiveExit) | ✅ | ⬛ fail-closed (no proof) | 🟡 real-but-unreachable | macOS exit = blind_exit, scoped follow-up `active_exit.rs:30-33` |
| blind_exit | ✅ (lan_toggle) | 🟥 no-op | 🟥 no-op | irreversible role, **unproven on mac/win** |
| role-switch matrix | ✅ (4 scored) | 🟡 host-only (top-level hard-fail) | 🟥 no Windows host branch | `live_linux_role_switch_matrix_test.rs:242` |
| two-hop | ✅ (but config-text-only, #8) | 🟥 no-op | 🟥 no-op | `enforce_linux_only…` |
| managed-DNS | ✅ (14 checks) | 🟥 hard-fail (peer-only) | 🟥 hard-fail (peer-only) | |
| lan-toggle | ✅ | 🟥 no-op | 🟥 no-op | |
| mixed-topology | ✅ (5) | ✅ 5/5 | ✅ 5/5 | **genuine parity** |
| network-flap | ✅ | 🟥 missing | 🟥 missing | |
| reboot-recovery | ✅ | 🟥 missing | 🟥 missing | |
| enrollment-restart | ✅ | 🟥 missing | 🟥 missing | |
| cross-network suite (8: direct/relay remote-exit, failback/roaming, controller-switch, node-switch, traversal-adversarial, remote-exit DNS, soak) | ✅ | 🟥 missing | 🟥 missing | the headline cross-NAT dataplane (D2–D13) — **Linux only** |
| chaos suite (8) | 🟡 5 real / 3 inert | 🟥 missing | 🟥 missing | see §4 |
| **nas role** | 🟥 missing | 🟥 missing | 🟥 missing | zero coverage anywhere |
| **llm role** | 🟥 missing | 🟥 missing | 🟥 missing | zero coverage anywhere |

Depth quantification: **macOS dedicated Rust test binaries = 1; Windows = 0.** The
`--platform` flag yields 4 behaviors: genuine parity (relay, mixed-topology),
real-but-narrower (exit-handoff — false green), top-level-hard-fail/host-only
(role-switch, managed-DNS, anchor partial), and total no-op (two-hop, lan-toggle).

---

## 3. Coverage Matrix B — exploitable / security surfaces × OS

Legend: ✅ real live producer+probe · 🟡 weak (config-only / static-payload /
producer-exists-but-unwired) · 🟥 missing.

| # | Security surface | Linux | macOS | Windows |
|---|---|---|---|---|
| 1 | Kill-switch / DNS fail-closed | 🟡 vacuous (#4) | ✅ (fixed last pass) | 🟡 latent-vacuous (behind Skip) |
| 1b | IPv6 leak | ✅ | ✅ | 🟥 missing |
| 2 | Exit-NAT teardown / no residual open relay | 🟥 **fail-open** (#1–#3) | ✅ (fixed) | ✅ (fixed) |
| 3 | Privileged-helper boundary (argv-only) | ✅ | 🟡 no live boundary test | ✅ |
| 4 | Key custody (storage/perms/startup) | ✅ | ✅ (rust-native `ValidateBaselineRuntime`→`MacosDaemonProbe`; CORRECTED) | ✅ (DPAPI) |
| 5 | Signed trust-state: verify + anti-replay + forged-bundle reject | ✅ | 🟥 missing (authenticode stub) | 🟡 binary-signing only |
| 6 | ACL / default-deny | ✅ | ✅ (rust-native `ValidateBaselineRuntime`→`MacosDaemonProbe`; CORRECTED) | ✅ |
| 7 | Endpoint hijack / server-IP bypass / rogue-path | ✅ | 🟥 missing | 🟥 missing |
| 8 | Control-surface exposure (socket/pipe) | ✅ | 🟡 anchor listener only | ✅ (named-pipe ACL) |
| 9 | Secrets never in logs | ✅ | 🟡 anchor-token only | 🟥 missing |
| 10 | NAT traversal / STUN / ICE adversarial | ✅ | 🟥 missing | 🟥 missing |
| 11 | Gossip / membership adversarial | ✅ | 🟥 missing | 🟥 missing |
| 12 | Enrollment-token (replay/forge/restart) | ✅ | 🟥 missing | 🟥 missing |
| 13 | Chaos: clock / crash / daemon-fault / exhaustion / impairment | 🟡 2 real, 3 inert | 🟥 missing | 🟥 missing |

**Surfaces untested on ALL three OSes:** clock-attack, crash-recovery,
resource-exhaustion (inert scaffolds, `bin/live_chaos_support/mod.rs`); relay
data-plane frame forwarding; nas/llm everything.

**Highest-risk Linux-only security gaps (mac/win completely exposed):** endpoint
hijack/server-IP-bypass (#7 — direct MITM of a mac/win node, unverified),
enrollment-token replay (#12), gossip poisoning (#11), STUN/ICE adversarial (#10),
signed-state forgery/replay (#5).

---

## 4. Capture-honesty findings (ranked) — captures that don't prove what they claim

Excludes the 4 items fixed last session (macOS DNS probe, macOS NAT merge,
Windows-exit teardown, demoted Windows contract stages). The pattern: the correct
anti-vacuous shape exists in-repo (`*_ipv6_leak.rs` `probe_attempted`;
`dns_block_probe.json`) but was applied **inconsistently** — Linux was left behind.

| # | Sev | File:line | Anti-pattern | Why weak / what a real proof needs |
|---|---|---|---|---|
| 1 | **CRIT** | `rustynetd/src/linux_exit_nat_lifecycle.rs:78,191-202` | fail-open | `capture_nft_nat_table(...).unwrap_or_default()` → `""` → `nat_table_present=false` = "torn down" on an `nft` error. Mirror macOS/Windows: a failed query ⇒ `present=true`. |
| 2 | **CRIT** | `rustynetd/src/linux_exit_nat_lifecycle.rs:181-210` | fail-open | failed `/proc/.../ip_forward` read defaults `"0"`→`"Disabled"`→"restored". Must canonicalize to `"Unknown"`. |
| 3 | **HIGH** | `scripts/e2e/capture_linux_exit_nat_lifecycle.sh:87-93`, `capture_linux_exit_demotion_residue.sh:92-97` | fail-open | Python merge defaults missing forwarding field to `"Disabled"` (the bug already fixed for macOS). Default `"Unknown"`. |
| 4 | **HIGH** | `vm_lab/mod.rs:15343` + `rustynetd/src/linux_exit_dns_failclosed.rs:106-120` | vacuous-pass | **live twin of the fixed macOS bug**: empty pcap passes, no active off-tunnel probe. Port the `dns_block_probe.json` / `dig` pattern + `probe_attempted` guard. |
| 5 | MED | `vm_lab/mod.rs:14599` + `require_empty_dns_pcap:15646` | vacuous (latent) | Windows DNS validator has no active-probe guard; latent behind a Skip today. Add the probe contract before wiring a Windows pcap producer. |
| 6 | MED | `vm_lab/mod.rs:15646-15654` `require_empty_dns_pcap` | vacuous (root helper) | the shared helper treats empty/"0 packets" as PASS with no probe notion — the root cause of #4/#5. |
| 7 | HIGH | `role_validation/relay.rs` + `vm_lab/mod.rs:17594-17624` | contract-only-as-pass | relay-lifecycle records Pass from `--dry-run` plan strings; **no OS forwards a real frame** through the relay or proves ciphertext-only / zero-ingress. |
| 8 | HIGH | `bin/live_linux_two_hop_test.rs:886,967-1021,1428` | config-text-only | "two-hop forwarding" asserted from status strings + `ip route get` text; **zero data-plane probe**. Needs an end-to-end probe past the final exit + per-hop evidence (TTL−2 / relay counter). |
| 9 | LOW-MED | `bin/live_linux_lan_toggle_test.rs:907` | weak-negative | a `ping` failure (any cause) satisfies "blocked"; mitigated by a positive control. Confirm enforced denial (route absent / killswitch drop). |
| 10 | LOW | `vm_lab/mod.rs:14871` + `capture_linux_exit_demotion_residue.sh:105` | never-asserted (partial) | demotion-residue during-run guard omits `internal_prefix==mesh_cidr`. |
| 12 | INFO | (no `windows_ipv6_leak.rs`) | coverage gap | Windows IPv6-leak entirely unproven (SecurityMinimumBar §8). |

**Exemplary stages to use as fix templates** (genuine behavioural proofs):
`rustynetd/src/{linux,macos}_ipv6_leak.rs` + validators (`mod.rs:14936,15003`) —
active `ping6` + BPF-filtered pcap + `probe_attempted` fail-closed; the just-fixed
`macos_exit_dns_failclosed.rs` (off-tunnel `dig` + `dns_block_probe.json`);
`macos_exit_nat.rs:121-181` (strict rule-shape evaluator); `live_linux_managed_dns_test.rs`
(real query + asserted answer + REFUSED negative + fail-closed adversarial guard).

---

## 5. External best-practice benchmark — what "thorough" means

(Sources: Mullvad `mullvadvpn-app/test/` + `pfctl-rs`, Tailscale `natlab`/`wf`/
`router`, ZeroTier CI, TUF spec, Jepsen/ByzzFuzz/proptest, Cure53/X41/RoS audit
reports. Full URL citations in the research tracks; key ones inline below.)

### 5.1 Leak proofs = active-probe negative test (the single most important pattern)
- **Gold standard = Mullvad's `test/` suite** (`tunnel_state.rs`, `dns.rs`,
  `helpers.rs`). The accepted way to *prove* no leak is a **negative test**: pick a
  marker destination not otherwise contacted, start a **libpcap monitor on the
  physical/non-tunnel NIC** filtered to it, **actively emit TCP+UDP+ICMP (and
  DNS:53/853) probes** (`send_guest_probes`), put the system in the dangerous state
  (tunnel up / **connecting** / **error** / **killed** / **network-changed**), and
  assert the monitor saw **zero** matching packets (`ProbeResult::none()`). A
  capture with no induced traffic proves nothing — that is exactly finding #4.
  Mullvad runs it during *transition* states, not just steady-state.
- **DNS specifics:** resolve **unique, uncached** hostnames via a tester-controlled
  authoritative resolver (dnsleaktest.com model) so the resolver's *real* egress is
  revealed regardless of config; assert only the tunnel resolver answers and zero
  :53 on the physical NIC. DoH/DoT bypasses egress on 443 — must be captured, not
  config-checked.
- **IPv6:** the seminal Perta et al. PoPETs-2015 result — most VPNs add only IPv4
  routes and leak *all* IPv6. Probe an IPv6-only destination and assert no native
  IPv6 egress (or assert IPv6 blackholed). Our `*_ipv6_leak.rs` already does this on
  Linux/macOS; Windows is missing (finding #12).
- → Rustynet: run kill-switch/DNS/IPv6 active-probe negative tests **during
  connect/error/reconnect/network-flap, on all 3 OSes**.

### 5.2 NAT traversal = a NAT-type matrix (Tailscale `natlab`)
- Tailscale simulates an **8×8 endpoint NAT-type pair grid** (Easy/Hard/symmetric
  per RFC 4787/5780), each cell asserting a *direct vs relay/DERP* verdict
  (`classifyPing`), with birthday-paradox port prediction for hard-NAT.
- → Rustynet's cross-network suite should run a **NAT-type × NAT-type matrix** and
  assert the achieved path (direct / relay / blocked) per cell — **including mac/win
  endpoints**, not just Linux netns.

### 5.3 Cross-OS firewall parity = assert the observable property, not rule text
- The robust pattern (Tailscale `Router` interface → `router_{linux,windows,
  darwin}.go`; Mullvad's per-OS killswitch) is one platform-neutral config consumed
  by three backends (nftables / pf / WFP-WinNAT), validated by **one external probe
  run identically on all OSes** — never by asserting backend-specific rule text
  (which is finding #8's config-text-only weakness, and #11's known limitation).
- Verification primitives to mirror: **WFP** exposes `Session.Rules()/Sublayers()`
  (assert filter installed) *and* an external probe (assert behavior); WFP `Block`
  overrides `Permit` across sublayers (formal default-deny) and **dynamic sessions
  auto-remove filters on process exit** (a teardown invariant a test can assert =
  no residual filter after daemon stop). **macOS pf**: Mullvad's Rust **`pfctl-rs`**
  (ioctl to `/dev/pf`) is the strongest Rust-first reference — Tailscale's darwin pf
  path is itself a known weak spot, so don't use it as the macOS model.
- → For every backend, the **first test is "empty/missing config ⇒ deny"** (our
  §10.4), then one external probe asserts the same property on all three.

### 5.4 Adversarial / chaos = Jepsen taxonomy + TUF attack catalog + ByzzFuzz
- **Jepsen nemesis fault families** (apply each per node, composably): network
  partition (iptables), process kill (`SIGKILL`), pause (`SIGSTOP/CONT`), **clock
  skew**, packet delay/loss/dup/corrupt (netem), **file corruption (bitflip/
  truncate)**. Drive ops from a deterministic generator, log a structured history,
  check invariants offline.
- **TUF attack catalog** = the required negative-test set for signed trust-state:
  **rollback** (replay an old-but-valid bundle with epoch < watermark ⇒ reject),
  **freeze** (stale/expired bundle ⇒ fail-closed, don't keep operating), **replay**,
  **mix-and-match**, **wrong-role/under-threshold key** (forged signer ⇒ reject),
  **version-skip** (N+2 while at N ⇒ reject; must apply N+1 first), **endless-data**
  (declared-size + hard cap on every bundle/zone/gossip fetch). Each must fail
  closed.
- **ByzzFuzz small-scope mutations** are the exact mutation set for signed bundles:
  *value* (bump epoch, flip a role bit, flip one signature bit) and *time* (re-inject
  a prior epoch) — keyed to gossip "rounds" (params d,c) so Byzantine testing is
  tractable. Maps directly to a tampered-signature / forged-key / replayed-bundle
  test trio. **Equivocation**: a malicious node gossips two conflicting same-epoch
  bundles to two partitions ⇒ network must detect/quarantine, not silently diverge.
- **Clock attacks**: `libfaketime` (`LD_PRELOAD`) gives **per-process** time control
  (set past expiry, jump backward) — more surgical than a global VM clock change;
  assert no early-trust on a backward jump and no premature expiry forward.
- **Crash-recovery**: `kill -9` mid-write of trust state (bundle / watermark / key
  store) at varied persistence points (kill-on-fsync, CharybdeFS/ALICE style); on
  restart assert atomic old-or-new state, **never a torn/partially-applied bundle
  that downgrades the watermark**. This is the real test the inert `crash_recovery`
  scaffold must become.
- **Property/model-based**: `proptest-state-machine` against an abstract reference
  model of role transitions enforces the §10.7 side-effect ordering (deploy-before-
  bundle, undeploy-before-revocation, exit-NAT-teardown-before-cap-removal,
  blind_exit irreversibility) and finds illegal-transition/residue bugs. Keep the
  existing `cargo-fuzz` targets coverage-guided with structure-aware `Arbitrary`.
- **Network impairment**: `tc netem` profiles (cellular: 200ms+jitter+5% loss+
  reorder; lossy-wifi: 15% loss+dup) with a fixed `SEED`; assert gossip convergence
  and that the anti-replay window tolerates reorder/dup without dropping legit
  frames.

### 5.5 Audit-grade evidence (so "passed the lab" ⇒ "audit-ready")
- Real VPN audits (Cure53 Mullvad/Mozilla/IVPN, X41 Mullvad, RoS infra) expect: a
  **written threat model with a coverage matrix** (leak / DoS-crash / privilege-esc
  / key-custody) where every test maps to it; **behavioral** kill-switch + leak
  proofs (incl. *before-login* and forced-reconnect); **negative/fail-closed** tests
  (empty config ⇒ deny) on every backend; **packet captures** as artifacts (not rule
  text); **reproducible builds verified by SHA**; **key-custody** review (Keychain/
  DPAPI, no backup/iCloud leak, no secrets in logs); **privilege-boundary** review
  (daemon socket/IPC access control, argv-only helper); and a **full published
  report including info-level findings**, across **all OSes**. WireGuard's protocol
  is treated as formally proven (Tamarin/CryptoVerif) — audit effort goes to the
  *integration/adapter*, exactly our backend-boundary model.
- **Calibration:** ZeroTier's own e2e is a *single* 2-node Linux-namespace harness
  gated only on "both online + no valgrind leak"; Windows is build-only. Rustynet's
  Linux depth already **exceeds** ZeroTier — the gap is purely cross-OS breadth +
  capture honesty, not Linux depth.

### 5.6 STRATEGIC: how mature projects achieve cross-OS parity (reframes Waves 2–4)
A survey of WireGuard, Tailscale, Headscale, Nebula, innernet, NetBird, ZeroTier
found that **none of them boots real macOS/Windows *multi-node* topologies** in CI.
Live multi-node topology testing is confined to **Linux** everywhere (netns / Docker
/ KVM-QEMU: WireGuard `netns.sh` 3-namespace, Tailscale `natlab`/`vnet` + `vms`,
Headscale `dockertest` `tsic`/`hsic`, Nebula in-process `router.R`, innernet
NET_ADMIN Docker). Cross-OS parity is achieved two cheaper ways instead:
1. **Isolate OS code behind a thin boundary and test the shared core once** (WireGuard
   file-suffix `tun_{linux,darwin,windows}.go` + in-process `ChannelTUN`; wireguard-go
   tests the portable core OS-independently).
2. **Run the *same* assertion binary on per-OS runners** (Tailscale runs its full
   sharded suite on Linux+Windows+macOS; Nebula unit-on-all-3, e2e Linux+macOS;
   NetBird per-OS workflows; ZeroTier selftest on Linux+macOS).

**Implication for Rustynet (cost-saving, and validating the existing design):** the
parity mandate's "every role live-proven on macOS AND Windows" is *more aggressive
than any of these projects' actual CI*. We do NOT need to stand up real mac/win
*meshes*. The right shape — which Rustynet's **`RemoteShellHost` trait already
delivers for its only two genuinely-parity areas (relay, mixed-topology)** — is one
assertion-logic body, argv-only per-OS remote-shell transport, run against a mac/win
node joined to an otherwise-Linux lab. So **Waves 2–3 = port the Linux assertion
binaries to drive mac/win nodes through the shared remote-shell trait**, not
re-implement topologies per OS. Wave 4's cross-network NAT-matrix is the one place a
richer substrate (à la Tailscale `natlab`) is warranted, and even there the mac/win
*endpoints* plug into a mostly-Linux fabric. Headscale's per-version-container
`assertPingAll` is the closest external analog to our role × OS matrix and a useful
template for the breadth waves.

---

## 6. The plan — what we build, in risk-ordered waves

Principle: **port the Linux depth to mac/win, fix the Linux honesty gaps, and add
the never-tested surfaces — using the active-probe / behavioural-proof shape
everywhere, no config-text-only or empty-capture passes.**

### Wave 0 — Honesty fixes (Linux + shared), small, high-value, no new lab
- Fix Linux exit-NAT teardown fail-open (#1–#3): `interpret_nft_capture(Err)⇒present`,
  `/proc` read fail ⇒ `"Unknown"`, shell merges default `"Unknown"`.
- Port the active DNS blocked-path probe to Linux (#4) and harden the shared
  `require_empty_dns_pcap` to require a `probe_attempted` companion (#5/#6).
- Replace relay-lifecycle `--dry-run`-as-Pass with a real forwarded-frame proof
  (#7); add a data-plane probe to two-hop (#8). These are Linux-authorable + unit-
  testable now.

### Wave 1 — Make degenerate integrated-pipeline cells honest in reporting
- Distinguish "reported-skip" from "Pass" at the `StageOutcome` level so a Windows
  relay / macOS anchor-runtime run does not show green (today only a side-car JSON
  reveals the skip). Add a `Skipped`/`NotProven` outcome surfaced in the parity diff.

### Wave 2 — Cross-OS parity for the CORE roles (port Linux Rust binaries to mac/win)
Build real macOS+Windows backings (via the `RemoteShellHost` trait that already
gives genuine parity for relay/mixed-topology) for: **two-hop, lan-toggle/
blind_exit, managed-DNS, role-switch matrix, exit-handoff *failover* (the real 6
checks, not the NAT-lifecycle substitute), network-flap, reboot-recovery,
enrollment-restart.** ~~Wire the unused macOS producers.~~ **CORRECTED: not needed**
— the macOS ACL/key-custody producers are already live-invoked by the rust-native
`ValidateBaselineRuntime`→`MacosDaemonProbe` path (the audit's "dead capability"
finding was wrong; see §0.7). The only dead code is the unused `daemon_probe_for`
helper, which is harmless.

### Wave 3 — Cross-OS parity for the SECURITY/adversarial surfaces (highest risk)
Port to macOS+Windows: **endpoint-hijack, server-IP-bypass, rogue-path,
enrollment-token replay/forge, gossip/membership adversarial, STUN/ICE traversal
adversarial, signed-state forgery/replay, secrets-not-in-logs, control-surface
exposure.** Add **Windows IPv6-leak** producer+validator (mirror Linux/macOS).

### Wave 4 — Cross-network dataplane (the headline capability) on mac/win
Parameterize the 8-stage cross-network suite (direct/relay remote-exit, failback/
roaming, controller-switch, node-switch, traversal-adversarial, remote-exit DNS,
soak) for macOS+Windows endpoints, with a Tailscale-natlab-style NAT-type matrix.

### Wave 5 — Fill the all-OS holes
Implement the 3 inert chaos scaffolds (clock-attack, crash-recovery,
resource-exhaustion) for real, on all 3 OSes; build the **nas** and **llm**
service-hosting-role live stages (currently zero coverage anywhere).

### Definition of done (live-lab thoroughness)
Every (role × OS) and (security-surface × OS) cell has a live stage that **actively
induces** the condition and **captures behavioural evidence** (probe + pcap /
translated-packet / per-hop / signed-reject), fails closed on capture error, is
not vacuous on empty capture, and is surfaced as a distinct non-Pass when skipped.
nas + llm included. Then "passed the live lab ⇒ deployable" holds.

---

## 7. Cross-references
- `CrossPlatformRoleParityPlan_2026-06-21.md` (the parity mandate + status matrix)
- `CrossPlatformRoleParityRoadmap_2026-06-22.md` (execution roadmap)
- `RustynetDataplaneExecutionPlan_2026-05-18.md` (cross-network D2–D13)
- `AutonomousSecurityParityPassLog_2026-06-24.md` (the prior honesty pass; this
  audit found the Linux twins of those same bugs)
- `SecurityMinimumBar.md` §8 (tunnel/DNS/IPv6 fail-closed)
