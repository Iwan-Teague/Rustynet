# Cross-Platform Role Parity — Completion Roadmap & Test-Pipeline Plan — 2026-06-22

**Purpose.** A single, concrete roadmap to drive macOS and Windows to full per-role
parity with Linux (the release-blocking mandate in
`CrossPlatformRoleParityPlan_2026-06-21.md`), **plus** an optimized live-lab test
pipeline that keeps both VMs busy and code always moving — all on the `main` branch.

This doc does not replace the parity plan; it **operationalizes** it. Precedence and
the authoritative status matrix stay in `CrossPlatformRoleParityPlan_2026-06-21.md`
(§3 matrix, §8 Definition of Done). The test *method* primitives stay in
`LiveLabExecutionEfficiencyPlan_2026-06-20.md`; this doc extends them to the parity
program and to **concurrent Windows+macOS** runs.

> All `file:line` citations below are against `main` at the time of writing
> (`origin/main = b63cbbe`). Verify before editing — line numbers drift.

---

## 0. TL;DR

- **What's left (mac/win):** of 7 roles × 2 OS, `LocalOnly` role transitions are
  now live-proven on BOTH macOS and Windows (2026-07-04); the genuine
  remaining work is anchor sub-surfaces beyond bundle-pull, the
  `SignedMembership` transition kind (both OS), Windows relay forwarding, and
  Windows exit lab enablement. Windows exit remains blocked on the lab
  guest's missing WinNAT stack, relay live forwarding remains HP-3-gated, and
  Windows blind_exit is out of scope by design.
- **Ordered program (after the now-live-proven anchor bundle-pull, admin,
  macOS exit, macOS relay-lifecycle, macOS blind_exit, and both `LocalOnly`
  role-transition cells):** the `SignedMembership` kind (design doc at
  `CrossOsRoleSwitchPlan_2026-06-24.md`) → remaining anchor sub-surfaces
  beyond bundle-pull. Relay forwarding and Windows exit/blind_exit remain
  explicitly parked with reasons.
- **Pipeline:** run a **Windows lab and a macOS lab simultaneously** on disjoint
  Debian backbones, iterate each role with **standalone SSH wrappers** against an
  already-warm guest (seconds, no 9-min bootstrap), and **write the next cell's code
  on `main` while both run**. One ~20-line `flock` on the run-matrix CSV is the only
  thing standing between us and fully-safe concurrency.
- **All on `main`:** two run kinds (§9). **Fast iteration** = `--skip-gates
  --source-mode working-tree` — the provenance gate doesn't run, so you test uncommitted
  edits and commit freely mid-run. **Authoritative evidence** = a clean, committed tree —
  the bash gate-suite intentionally refuses dirty/HEAD-drifted attestation (this is what
  aborted "chaos3"; it's a feature). The node-map session lives on its own branch, so
  `main` is free. No feature branches required.
- **Industry-grounded (Appendix A):** the cells inherit the proven patterns of the mature
  mesh-VPNs — relay-never-sees-plaintext (DERP/Firezone/Nebula) with a negative live test,
  exit/relay double-opt-in (Tailscale), single-use scoped enrollment tokens with
  client-side keygen (innernet/NetBird), signer-stamped freshness + bounded rollback
  window (ZeroTier), gossip revocation, and a WireGuard-adapter invariant contract. No
  custom crypto.

---

## 1. Where we are — the role × OS picture

Restated from `CrossPlatformRoleParityPlan_2026-06-21.md` §3 (legend: ✅ live-proven ·
🟡 implemented, not yet run green live · 🟠 contract/dry-run validator only · ❌
untested/not implemented · 🔒 blocked):

| Role | Linux | macOS | Windows |
|---|---|---|---|
| client | ✅ | ✅ | ✅ (active client traffic pending cross-OS run) |
| admin (mint/issue signed bundles) | ✅ | ✅ **LIVE-PROVEN** (refresh run `labrun-1783089250895-6139-0`, commit `831d41d`, `validate_macos_admin_issue` PASS: signed assignment issue, local verify, rollback/tamper reject, Linux peer verify-before-apply accept/reject) | ✅ **LIVE-PROVEN 2026-06-27** (`validate_windows_admin_issue` PASS, run `livelab-1782526081`) |
| anchor (gossip/bundle-pull/enrollment) | ✅ | ✅ **bundle-pull LIVE-PROVEN 2026-06-22** (`validate_macos_anchor_bundle_pull` PASS; gossip/enrollment remain tracked separately) | ✅ **bundle-pull LIVE-PROVEN 2026-07-03** (`validate_windows_anchor_bundle_pull` PASS, run `labrun-1783079551578-32671-0`, commit `786f900`; loopback byte-for-byte + token gate + LAN refused + secrets hygiene; gossip/enrollment remain tracked separately) |
| exit (NAT egress + killswitch) | ✅ | ✅ **LIVE-PROVEN 2026-07-03** (`labrun-1783087254263-11121-0`, commit `039f215`: activation, NAT lifecycle, DNS fail-closed, service hardening, mesh-status) | 🟡 implemented but **🔒 lab guest lacks WinNAT/`MSFT_NetNat`** |
| blind_exit (irreversible exit) | ✅ | ✅ **LIVE-PROVEN 2026-06-29** (run `labrun-1782770042330-16244-0`, `--blind-exit-platform macos`): `validate_macos_blind_exit` PASS — irreversible transition applied, pf anchor hardened (9 rules, no route-to/reply-to/dup-to), immutability gate enforced | 🚫 **blocked by design** (`main.rs:11768` hard-errors; macOS/Linux only) |
| relay (live session forwarding) | ✅ *(lifecycle only — no live forwarding proof anywhere; see §4)* | ✅ **lifecycle LIVE-PROVEN 2026-06-27** (run `livelab-1782571161`, `validate_macos_relay_service_lifecycle` PASS). **Live session forwarding remains HP-3-gated** (same cross-OS gate as Linux ✅). | 🟠 SCM lifecycle contract only |
| live role transitions (cross-OS) | ✅ (`role_switch_matrix`) | ✅ **LIVE-PROVEN 2026-07-04** (`validate_macos_role_transition`, `LocalOnly` admin<->client, run `livelab-1783135864-2fda3979d599`) | ✅ **LIVE-PROVEN 2026-07-04** (`validate_windows_role_transition`, `LocalOnly` admin<->client, run `livelab-1783174602-844175f5ad2a`, commit `5516711`) |

**Three corrections this roadmap has made to the matrix:**
1. macOS **admin** is live-proven; the "self-mint deliberately disabled" note had
   no backing in code or `SecurityMinimumBar` (§4).
2. **Windows blind_exit** is not a gap to close — it is an intentional platform
   exclusion (`main.rs:11768`). Re-label ❌ → 🚫 (out of scope, like mobile clients).
3. macOS **blind_exit** is now ✅ Live-Proven (2026-06-29, run `labrun-1782770042330-16244-0`); cell 3 closed.

---

## 2. Remaining work per role (mac/win) + effort

Effort is focused-engineering time *including* live iteration on the VM (live bugs only
surface live — the macOS anchor cell took 3 live runs to expose an SSH-user defect a
dry-run had masked). "Live stage" = author a fail-loud stage per §7.

| # | Cell | Status | What's needed | Effort | Gating |
|---|---|---|---|---|---|
| — | macOS anchor | ✅ DONE for bundle-pull | live-proven 2026-06-22; remaining gossip/enrollment/port-map sub-surfaces stay separate | — | — |
| 1 | **macOS admin** | ✅ DONE | refresh proof: `labrun-1783089250895-6139-0`, `831d41d`, `validate_macos_admin_issue` PASS | — | — |
| 2 | **Windows admin** | ✅ DONE | live-proven 2026-06-27: `validate_windows_admin_issue` PASS, run `livelab-1782526081` | — | — |
| 3 | **macOS blind_exit** | ✅ DONE (2026-06-29) | live-proven: `labrun-1782770042330-16244-0`, `ed3ed7e` | — | — |
| 4 | **Role transitions (macOS + Windows)** | ✅ macOS `LocalOnly` DONE (2026-07-04); ✅ Windows `LocalOnly` DONE (2026-07-04) | macOS: `validate_macos_role_transition` PASS, run `livelab-1783135864-2fda3979d599`, commit `2fda397`. Windows: `validate_windows_role_transition` stage built + committed (`8816bf7`); its first live run (`livelab-1783142381-8816bf73333b`) FAILED on a genuine capability gap (the deployed Windows guest CLI had no daemon IPC client and `update_node_role_env_file` didn't parse the `RUSTYNETD_DAEMON_ARGS_JSON` array format) — both closed by `c51f00a` (named-pipe IPC client + env-file fix). Re-run `livelab-1783174602-844175f5ad2a` (commit `5516711`) PASSED: client->admin flip, service restart verified, state refresh ok, mesh peers before=0 after=0. `SignedMembership` kind remains design-only for both OS | — | admin + role-transition cells done |
| 5 | macOS **exit** | ✅ DONE | live-proven 2026-07-03 by `labrun-1783087254263-11121-0` on `039f215` | — | — |
| 6 | macOS **relay** *live lifecycle* | ✅ **DONE** (2026-06-27) | ✅ live lifecycle proven: `validate_macos_relay_service_lifecycle` PASS (run `livelab-1782571161`). **Forwarding proof remains HP-3-gated, same as Linux.** | — | — |
| 7 | Windows **anchor** live + macOS **anchor** live | ✅ DONE for bundle-pull | macOS bundle-pull live-proven 2026-06-22; Windows bundle-pull live-proven 2026-07-03 via `labrun-1783079551578-32671-0` on `786f900`; remaining gossip/enrollment anchor sub-surfaces stay separate | — | — |
| 🔒 | Windows **relay** forwarding | 🟠 | nothing to author until a Linux live two-peer forwarding stage exists | — | **HP-3** (`MasterWorkPlan` HP-3 — "most substantial remaining code item"; weeks) |
| 🔒 | Windows **exit** | 🟡 | code done (`promote_windows_exit_active`); needs a WinNAT-capable guest | — | lab env (`MSFT_NetNat` absent) |
| 🚫 | Windows **blind_exit** | — | out of scope by design (`main.rs:11768`) | — | n/a |

**Bottom line:** the `LocalOnly` role-transition slice is live-proven on BOTH
macOS and Windows (2026-07-04). The Windows half was briefly blocked on a
genuine capability gap (no Windows CLI exposed `role status`/`role set`/
`state refresh`), discovered by that stage's first live run and closed by
`c51f00a`. Remaining implementable parity work is the `SignedMembership`
transition kind (both OS), plus explicit anchor gossip/enrollment/port-map
live proof. Relay forwarding stays HP-3-gated, and Windows exit stays
blocked by the lab guest's missing WinNAT/HNS stack.

---

## 3. How each role plugs in — the four-layer seam

Every role traverses the same seam; mirror the patterns by file:

1. **Capability → role-transition planner.** `crates/rustynet-cli/src/role_cli.rs`
   turns a role preset into ordered `ConcreteAction`s (deploy-service-before-bundle,
   NAT-teardown-before-capability-removal, the `BlindExitImmutable` gate at
   `role_cli.rs:199,220-224,333,355`). Canonical validator mirrored by MCP
   `get_role_transition`.
2. **Per-OS service unit + installer.** macOS launchd via
   `crates/rustynet-cli/src/ops_install_macos_exit.rs` / `ops_install_macos_relay.rs`
   (+ `ops_install_macos_anchor.rs`, landing); Windows SCM via
   `crates/rustynetd/src/windows_service.rs` + reviewed PowerShell helpers.
3. **Dataplane adapter.** Linux nftables; macOS `pf`
   (`macos_exit_killswitch_precedence.rs`, `macos_exit_nat_lifecycle.rs`,
   `macos_exit_dns_failclosed.rs`, `macos_blind_exit.rs`); Windows netsh/WinNAT/WFP via
   `phase10.rs` `WindowsCommandSystem` + `set_relay_forwarding` (`phase10.rs:1749`).
4. **Live-lab stage.** `run_macos_orchestration_stages` (`vm_lab/mod.rs:7897`, fired by
   `--macos-vm`) and `run_windows_orchestration_stages_with_options` (`vm_lab/mod.rs:9851`,
   fired by `--windows-vm`). **FAIL-LOUD reference:** the macOS exit stage at
   `vm_lab/mod.rs:8568-8712` (`is_macos_active_exit` true only when `--macos-vm ==
   --exit-vm`; live evidence capture; Pass/Fail strictly from the live result; downstream
   validators chain only on the live pass at `:8633`).

**SSH composition (every live exerciser must do this):** inventory carries `ssh_target`
and `ssh_user` as separate fields (`VmInventoryEntry`, `vm_lab/mod.rs:1681-1699`); compose
`user@host` via `remote_target_from_inventory_entry` (`2972-2984`) / `normalized_ssh_target`
— never hardcode the user. (The macOS anchor cell's 2nd live bug was exactly this: it
SSHed as `iwan@` instead of `mac@`.)

**Anti-pattern to never repeat:** `validate_macos_anchor_bundle_pull`
(`vm_lab/mod.rs:8915-8961` → `9340-9377`) records **Pass** from a `--dry-run` plan-text
check without serving a bundle; the old Windows anchor contract validator
(`validate_windows_anchor_bundle_pull_plan_contract` `:9516`) had the same defect
until it was replaced by the 2026-07-03 live guest-touching
`validate_windows_anchor_bundle_pull` run. The Windows relay contract validator
(`validate_windows_relay_service_lifecycle_contract` `:9565`) still runs entirely
in-process against repo files ("without guest mutation") and remains the exact
defect §7 forbids for relay.

---

## 4. Dependency & scope analysis (decisive)

### RELAY (both OS) — GATED on HP-3
**No live stage on any OS forces two peers through a relay and asserts forwarded
packets.** `validate_relay_lifecycle`
(`vm_lab/orchestrator/role_validation/relay.rs:130-212`) proves the unit is active, the
datapath (`:4500`) and health (`:4501`) listeners are bound, `/healthz` returns `ok`, and
all of that is gone after stop then restart — but it **never drives a peer through the
relay**. Real forwarding is **HP-3 "Production Relay Transport Service"** in
`MasterWorkPlan_2026-03-22.md` ("the most substantial remaining code item … relay path
is just a routing label — no actual packets are relayed"). Code modules exist
(`rustynet-relay/src/{transport,session,rate_limit}.rs`) but live cross-network evidence
is pending. **Status update (2026-06-27): macOS relay *lifecycle* is now LIVE-PROVEN**
(run `livelab-1782571161`, `validate_macos_relay_service_lifecycle` PASS —
install/bootstrap → active `/healthz` → stop/release). The loopback `/healthz` wedge was
fixed by `574eaac` (loopback exemption in `render_macos_killswitch_pf_rules`). **Conclusion:**
macOS relay lifecycle is at parity with Linux. macOS/Windows relay *live forwarding*
parity cannot be authored until HP-3 lands a Linux two-peer forwarding stage; once that's
green and a `--relay-platform` selector points it at a mac/win relay, parity is a port.

### ADMIN (both OS) — IN SCOPE; "consumer-only" framing is stale
The matrix note "macOS is a pure consumer; self-mint deliberately disabled" is **not**
backed anywhere: `find_in_docs` for the rationale returns no matches across 153 docs; the
only occurrence is the matrix cell. The canonical validator reports `admin` as ✅
supported on macOS **and** Windows, with `client → admin` a "local-only (config write +
daemon reload), no signed bundle" transition. No `can_mint`/`self_mint` platform gate
exists in code. **Conclusion:** admin is the most tractable unproven cell — the
signing/issuing machinery (`ops e2e-issue-assignment-bundles-from-env`,
`main.rs:4500-4519,5552`) is platform-neutral Rust already used on Linux; mac/win just
need a live stage that runs it on the guest and has a peer ingest the result. Custody is
already correct (`keychain-secrets` macOS / `dpapi-secrets` Windows). Correct the doc;
don't silently rely on a stale "disabled" note.

### ROLE TRANSITIONS (both OS) — need a DESIGN doc first
**UPDATE 2026-07-04: superseded — both macOS and Windows `LocalOnly` role
transitions are now built AND live-proven; see the ordered-roadmap table
above and `CrossOsRoleSwitchPlan_2026-06-24.md`'s status header.** The
original gap analysis below is kept for historical context.

`CrossOsRoleSwitchPlan_2026-06-24.md` now holds this design (the gitignored `state/` path could not persist; matrix cited it as "banked"
— it isn't). The runtime to reuse exists: `refresh_signed_state_with_reason`
(`daemon.rs:4487-4526`) is the single verified apply path (re-fetch trust → traversal →
assignment → dns_zone, fail-closed on every error); IPC `StateRefresh`
(`ipc.rs:44,201`; `daemon.rs:7156`) is the trigger; the current `role_switch_matrix`
stage only verifies tunnels stay active, it doesn't drive a real flip. **Conclusion:**
author a short design doc (define the launchd/SCM role-flip → `role set` →
emit/ingest signed bundle or local-only config write → `StateRefresh` → assert the new
role's dataplane is live), then the stage. Sequence **after admin** (a transition's
issuing half depends on it).

### BLIND_EXIT — macOS near-ready (safe live test); Windows out of scope
macOS runtime exists (`macos_blind_exit.rs`: pf anchor, local-origin egress tunnel-only,
forwarded egress mesh-CIDR-only, no `route-to`/`reply-to`); the irreversibility gate is
enforced (`role_cli.rs:199,220-224,355`, factory-reset recovery only). **Safe to test
live on macOS** — the lab guest is disposable; the next run's bootstrap re-provisions a
fresh identity, so the destructive wipe is recoverable in-lab. Run the stage **last** in
the macOS sequence and only under an explicit `--blind-exit-platform macos` selector.
**Windows blind_exit is blocked by design** (`main.rs:11768` "supported on Linux/macOS
only"; validator says `🚫 blocked`) — exclude it, correct the matrix.

---

## 5. Ordered implementation roadmap

Rank = value ÷ (tractability · safety). After **anchor (done for bundle-pull)**
and **macOS exit** (LIVE-PROVEN 2026-07-03 by
`labrun-1783087254263-11121-0` from `039f215`: activation, NAT lifecycle,
DNS fail-closed, service hardening, and mesh-status all passed; `partial` only
from selector/optional skips):

| # | Cell | Why this rank |
|---|---|---|
| ✅ | **Role transitions (macOS + Windows)** | macOS `LocalOnly` DONE: `validate_macos_role_transition` PASS, run `livelab-1783135864-2fda3979d599`, commit `2fda397` (client->admin flip, launchd reload, `state refresh`, mesh-peer-regression check). Windows `LocalOnly` DONE 2026-07-04: stage built (`8816bf7`), briefly blocked on a missing IPC client + an `update_node_role_env_file` format mismatch, both closed by `c51f00a` — re-run `livelab-1783174602-844175f5ad2a` (commit `5516711`) PASSED (client->admin flip, service restart, `state refresh`, mesh-peer-regression check). `SignedMembership` kind remains design-only for both OS |
| 2 | **Remaining anchor sub-surfaces** | bundle-pull is live-proven on macOS/Windows; macOS `port_mapping_authoritative` live-proven 2026-07-04 (`validate_macos_anchor_port_mapping_authority`, run `livelab-1783159711-65e19f7cdb49`); gossip_seed/enrollment_endpoint (both OS) and port_mapping_authoritative (Windows) still need explicit live proof — enrollment_endpoint has zero runtime enforcement today and needs a design+implementation pass first |
| ✅ | **macOS admin** | DONE: `labrun-1783089250895-6139-0`, commit `831d41d`, `validate_macos_admin_issue` PASS |
| ✅ | **Windows admin** | DONE: `livelab-1782526081`, `validate_windows_admin_issue` PASS |
| ✅ | **macOS blind_exit** | DONE: live-proven 2026-06-29 |
| 5 | **macOS relay live lifecycle** | ✅ **DONE** (live-proven 2026-06-27); forwarding stays HP-3-gated |
| 6 | **Windows + macOS anchor bundle-pull live** | ✅ **DONE** (macOS 2026-06-22; Windows 2026-07-03 `labrun-1783079551578-32671-0`); remaining anchor gossip/enrollment/port-map proof is separate |
| 🔒 | Windows relay forwarding | blocked on HP-3 (no live forwarding proof anywhere) |
| 🔒 | Windows exit | blocked on WinNAT guest (code done) |
| 🚫 | Windows blind_exit | out of scope by design |

---

## 6. First three implemented cells — file-by-file

### Cell 1 — macOS admin (mint/issue signed bundle, live) — DONE
- **Runtime:** none new. Reuse the platform-neutral issuing verbs
  (`e2e-issue-assignment-bundles-from-env` / `assignment issue`,
  `main.rs:4500-4519,5552`) + keychain custody (`macos_key_custody.rs`). Confirm
  `role set admin` is a local-only config write on macOS.
- **Live stage** in `run_macos_orchestration_stages` (`vm_lab/mod.rs:7897`), before the
  relay/anchor block, mirroring the macOS-exit FAIL-LOUD shape (`8568-8635`):
  - Add an `admin_platform: Option<String>` config field next to
    `exit_platform`/`relay_platform`/`anchor_platform` (`vm_lab/mod.rs:911-922`); compute
    `is_macos_active_admin` like `is_macos_active_exit`.
  - Add `exercise_macos_admin_issue_live` (mirror `capture_macos_exit_evidence_artifacts`,
    `9010`): resolve the target via `remote_target_from_inventory_entry`; SSH-run
    `rustynet role set admin` then `assignment issue …`; SCP the bundle back; have a
    **Linux peer ingest it live** and assert the peer applied it (reuse
    `orchestrator/adapter/linux_membership.rs`). Stage status = live result; Fail on any
    step failure. A `--dry-run` render may be an informational artifact, never a Pass.
- **Security (enforcement + test):** signing key from OS-secure store only; peer does
  verify-before-apply (signature → epoch/anti-replay watermark → apply, §10.5); malformed
  bundle → peer fails closed (default-deny); append-only audit entry; never log key
  material. Tests: unit on the selector + issue-then-ingest parser; negative integration
  "peer rejects an admin bundle with a stale watermark".
- **Lab command:**
  ```
  target/debug/rustynet-cli ops vm-lab-orchestrate-live-lab \
    --inventory documents/operations/active/vm_lab_inventory.json \
    --ssh-identity-file <id> --known-hosts-file <kh> --report-dir state/live-lab-macadmin \
    --legacy-bash-orchestrator --stage-timeout-secs 1500 --skip-gates \
    --exit-vm debian-headless-1 --client-vm debian-headless-2 --entry-vm debian-headless-3 \
    --macos-vm macos-utm-1 --admin-platform macos --skip-soak --skip-cross-network \
    --source-mode working-tree
  ```

### Cell 2 — Windows admin (mint/issue signed bundle, live) — DONE
- **Runtime:** none new — same issuing verbs; DPAPI custody exists
  (`windows_key_custody.rs`).
- **Live stage** in `run_windows_orchestration_stages_with_options` (`vm_lab/mod.rs:9851`):
  add `exercise_windows_admin_issue_live` modeled on `promote_windows_exit_active`
  (`10583-10630`) — drive the reviewed PowerShell helper to run `role set admin` +
  `assignment issue` on the guest, SCP the bundle back, peer ingests live. **Replace** the
  in-process `validate_windows_*_contract` Pass with this guest-touching result (the
  contract check may remain an informational pre-check only).
- **Security:** DPAPI custody; verify-before-apply + anti-replay on the peer; don't strip
  the SYSTEM ACE off the control channel (`vm_lab/mod.rs:1607-1614`); argv-only helper
  exec (no `Invoke-Expression`/`cmd /c`, already forbidden at `9628-9633`); append-only
  audit. Tests: helper-output parser unit + stale-bundle negative + live row.
- **Lab command:** as Cell 1 but `--windows-vm windows-utm-1 --admin-platform windows`
  (drop `--macos-vm`).

### Cell 3 — macOS blind_exit (irreversible exit, live, run last) — DONE
- **Runtime:** already present (`macos_blind_exit.rs`,
  `build/evaluate_macos_blind_exit_pf_rules`, wired `phase10.rs:2457,2653,2967`); gate
  enforced (`role_cli.rs:199,220-224,355`).
- **Live stage** in `run_macos_orchestration_stages`, **after** exit and admin (it wipes
  identity): add `exercise_macos_blind_exit_live` (mirror `capture_macos_exit_evidence_
  artifacts`, `9010`): SSH-run `exit → blind_exit` with the typed factory-reset ack,
  capture the live `pf` ruleset, assert via `evaluate_macos_blind_exit_pf_rules` that (a)
  the anchor is present, (b) local-origin egress is tunnel-only, (c) forwarded egress is
  mesh-CIDR-only, (d) no `route-to`/`reply-to`. Negative check: a reverse transition fails
  closed. Stage status = live result.
- **Security:** immutability gate (verify reverse `role set` fails), fail-closed pf
  default-deny, DNS fail-closed if `dns_protected`, no-`route-to` invariant, append-only
  audit of the destructive transition.
- **Safety:** guest is disposable; next run's bootstrap re-provisions identity. Gate the
  stage on `--blind-exit-platform macos` so it never wipes a guest mid-suite.
- **Lab command:** as Cell 1 but `--blind-exit-platform macos --report-dir
  state/live-lab-macblindexit`.

---

## 7. FAIL-LOUD live-stage spec (every parity stage MUST follow)

The macOS anchor cell taught the rule the hard way: its dry-run *fallback* recorded
**Pass** while the live SSH path silently failed (wrong SSH user). Never again.

1. **Live result IS the stage status.** The stage performs the role's runtime action
   against the real guest over SSH (compose `user@host` from inventory `ssh_user` +
   `ssh_target`/`last_known_ip`) and sets Pass/Fail strictly from the live outcome — like
   the macOS-exit stage (`vm_lab/mod.rs:8604-8631`). The only non-Pass/non-Fail states
   allowed: `Skipped` when the role isn't elected onto this OS (`!is_macos_active_exit`,
   `8586`), or a strict prerequisite stage didn't pass (`!mesh_join_passed`, `8596`).
2. **No dry-run-as-pass, ever.** A `--dry-run`/plan-contract check may be an
   *informational artifact* but never substitutes for a live Pass. The anti-examples to
   delete/replace: the old `validate_macos_anchor_bundle_pull` dry-run fallback
   (`8915-8961`) and the Windows relay contract validator (`9565`) that never
   touches the guest. The prior Windows anchor contract validator was superseded
   by the 2026-07-03 live `validate_windows_anchor_bundle_pull` run.
3. **Chain on the live result.** Downstream validators run only if the live capture
   passed (`macos_exit_capture_passed`, `8633`) — never skip-to-pass.
4. **Assert the role's security controls LIVE** on the guest: killswitch precedence, DNS
   fail-closed, signed-state verify-before-apply (signature → watermark → apply),
   anti-replay, default-deny ACL/route — captured as artifacts and asserted, not assumed.
5. **A non-elected/unverifiable node is never a silent Pass.** Follow `verify_tunnels_
   active` (`role_switch_matrix.rs:14-26`): an unverifiable node (e.g. `wg-not-installed`)
   is a **Fail**. Record every run's row in `live_lab_run_matrix.csv`.

---

## 8. Efficient testing & the always-busy VM pipeline

This is the answer to "minimal downtime — always using the VMs, always writing code."
It extends `LiveLabExecutionEfficiencyPlan_2026-06-20.md` (the verified primitives:
setup/run split, per-node rebuild, single-stage wrappers, deploy preview) with **fast
per-role loops** and **concurrent Windows+macOS** runs.

### 8.1 Three iteration speeds (pick by what changed)
| Change | Loop | Cost | Mechanism |
|---|---|---|---|
| Re-run **one role's assertions** (no code change, or test-harness only) | **standalone wrapper** against the warm guest | seconds–minutes | `scripts/e2e/live_macos_<role>_test.sh` / `live_windows_<role>_test.sh` SSH the already-running host; no bootstrap (`bin/live_linux_anchor_test.rs:2394-2452`; wrappers are thin `--platform` shims) |
| **Daemon code** changed on one node | `--rebuild-nodes <alias>` | one node's ~9-min build; others stay warm | `orchestrator/stage/install.rs:17-22,63-68` + `cleanup.rs:44-51` limit cleanup+bootstrap to the named alias |
| **Orchestrator/test (`rustynet-cli`)** changed | rebuild local binary only | local `cargo build` | nothing ships to guests |
| **Authoritative "section done"** | one clean full orchestrate + matrix row | full run | reliability gate (`LiveLabExecutionEfficiencyPlan` §3) |

**Keep-warm:** bootstrap is a guest-side `cargo build` budgeted at 900s
(`orchestrator/adapter/linux_install.rs:65`; macOS `macos_install.rs:124-148`; Windows
`windows_install.rs:133+`). `--rebuild-nodes` with a **subset** rebuilds only those;
with an **explicit empty set** rebuilds **nothing** (every node reused as-is —
`install.rs:134-138`), giving a validate-only pass with zero bootstrap cost.

### 8.2 Fast per-role inner loop (the big win)
Bootstrap a target VM **once**, then iterate a single role in seconds:
```
bash scripts/e2e/live_macos_anchor_test.sh \
  --ssh-identity-file <id> --known-hosts <kh> \
  --anchor-host mac@192.168.0.210 --anchor-node-id macos-client-1 \
  --leaf-client-host debian@192.168.0.204 --leaf-client-node-id extra-1 \
  --report-path artifacts/macos_anchor_$(date +%s).json
```
Edit the stage/role code → re-run the wrapper → read the JSON report. Only when the
**daemon binary** itself changed do you re-deploy that one node
(`... vm-lab-orchestrate-live-lab ... --rebuild-nodes macos-utm-1`).
(Harness-coupled stages — chaos, soak — don't run standalone; use a scoped run for those.)

### 8.3 Concurrent Windows + macOS labs (disjoint backbones)
Two `orchestrate` runs on **disjoint node sets** with **separate `--report-dir`** are
safe to run at the same time. The macOS/Windows parity stages fire on `--macos-vm` /
`--windows-vm` (`vm_lab/mod.rs:6956/7059/7369`), independent of each other.

**Node partition (6 Debian available: .200–.204 + .11):**
- **Run A (Windows):** `--exit-vm debian-headless-1 --client-vm debian-headless-2
  --entry-vm debian-headless-3 --windows-vm windows-utm-1` → report `state/live-lab-win-*`
- **Run B (macOS):** `--exit-vm debian-headless-5 --client-vm debian-headless-4
  --entry-vm debian-lan-11 --macos-vm macos-utm-1` → report `state/live-lab-mac-*`

**Shared-resource audit (verified):** host source archive is PID-scoped
(`source_archive.rs:127-129`); `network_id` is timestamp-unique (`mod.rs:6638-6644`);
guest `/tmp` paths are fixed but only collide if the **same guest** is in both runs
(disjoint partition avoids it); report dirs are per-run and reuse is rejected
(`mod.rs:6630`). **The one genuine host-side collision is the un-locked run-matrix CSV
append** (`live_lab_run_matrix.rs:1528-1560` does read→write→append with no `flock`) — two
runs finishing near-simultaneously can interleave. **Enabling fix (§11.1):** wrap the
append in an advisory `flock` (~20 lines). Until then, stagger the two completions or
append the second run's row by hand.

**One thing to verify on the first concurrent run:** Run B's `--exit-vm` is a
Debian node not flagged `exit_capable` in the inventory (only `debian-headless-1` is). For
a non-exit parity role (admin/anchor/blind_exit) the backbone exit is just the
coordinator/signer, but confirm the bash backbone accepts it — or mark a second Debian
`exit_capable` via `--update-inventory-live-ips` (never hand-edit the JSON).

### 8.4 The always-busy pipeline
Three things in flight at once, no idle:
1. **Windows VM** runs Run A (a Windows cell's live validation).
2. **macOS VM** runs Run B (a macOS cell's live validation).
3. **You write the next cell's code on `main`** (working-tree edits don't perturb either
   in-flight run — the deployed tarball froze at stage 2).

When a run frees a VM, drop into the §8.2 per-role wrapper loop on that VM to nail the
last failures fast, then promote to a clean full run for the matrix row. Batch the heavy
gates (`cargo test --all-targets`, `audit`, `deny`, ~48 min) in the background so they're
done when a cell is ready to land.

---

## 9. All on `main` — the workflow

The user constraint: **do all of this on `main`, not a feature branch.** This works — but
"can I commit during a run?" is **path- and stage-dependent**. There are **two** provenance
mechanisms; know which is in your path:

1. **`validate_setup_manifest`** (`vm_lab/mod.rs:2584`) re-checks HEAD, but is called
   **only** from the `setup`/`run` split subcommands (`:2784`, `:5107`) — **never** from
   `orchestrate`. **Rule: always use `orchestrate`; never the `setup`→`run` split for
   parity work.**
2. **The bash orchestrator's `assert_local_gate_suite_provenance`**
   (`scripts/e2e/live_linux_lab_orchestrator.sh:4863-4882`) is a **second, live** HEAD
   re-read that runs **inside the local-full-gate-suite stage** (defined `:4941-4947`,
   dispatched `:8569`). It **fails closed** if (a) live HEAD drifted from the deployed
   commit, (b) `--source-mode working-tree` **and** the tree is dirty, or (c) the source
   tree is dirty at all. **This is what aborted "chaos3"** when a concurrent session
   committed to `main` mid-run. It is an **evidence-integrity control, not a bug** — the
   authoritative gate suite refuses to attest a run whose source isn't clean and
   commit-bound. **Do not weaken it.** It is **skipped under `--skip-gates`** (`:8025`,
   `:8574`), and the rust-native `--node` path has no equivalent.

**So the correct all-on-`main` loop has two run kinds:**

- **Iteration run (fast, frequent):** `--skip-gates --source-mode working-tree`. The
  provenance gate does **not** run, so you ship *uncommitted* tracked edits (`git stash
  create` snapshot at stage 2, `source_archive.rs:52-68` — `git add` new files first;
  untracked aren't captured), validate the cell's live stage, and **commit freely** —
  mid-run commits cannot break these. This is the per-cell inner loop.
- **Authoritative "section done" run (the matrix-row evidence):** a **clean, committed**
  tree with `--source-mode local-head`. If you also drop `--skip-gates` to run the host
  gate suite, the provenance gate **requires** that clean-committed tree — so **commit
  first, run clean, do not commit during it.** That clean run is the authoritative parity
  evidence (`LiveLabExecutionEfficiencyPlan` §3). Commit-bound evidence is a security
  property, not an obstacle.

**Why `main` is free:** the node-map session commits to
`claude/rustynet-node-map-visual-mmclho`, not `main`, so its work never moves `main`'s
HEAD. Parity dev and lab runs own `main`.

**Concrete loop, all on `main`:**
```
# (on main, in the lab-main worktree which tracks main)
edit cell code → cargo fmt + clippy -p <crate> + touched-crate tests
→ orchestrate ... --skip-gates --source-mode working-tree   # fast iteration; ships uncommitted edits; commit-freely-safe
→ iterate until the cell's live stage is green
→ git add -A && git commit (Iwan-Teague, NO Co-Authored-By trailer)
→ orchestrate ... --source-mode local-head   # CLEAN authoritative run on the committed tree → matrix row
→ green? push origin HEAD:main → next cell
```

**Two practical notes:**
- **Worktree vs. checkout.** `main` currently lives in the `.claude/worktrees/lab-main`
  worktree; the primary checkout (`/Users/iwan/Desktop/Rustynet`) is on the node-map
  branch because that session holds it. All parity commits go to the `main` *branch* (via
  lab-main) and push to `origin/main` — that **is** "on main." To make the primary
  checkout literally show `main`, either (a) let the node-map session land/merge its
  branch into `main` first, then `git checkout main` there, or (b) merge
  `claude/rustynet-node-map-visual-mmclho` → `main` so there's a single branch. That's a
  coordination call with the node-map session, not a blocker for parity work.
- **Commit authorship.** All commits are authored/committed by Iwan-Teague with **no**
  `Co-Authored-By: Claude` trailer (repo policy — overrides the global default).

---

## 10. Definition of Done & tracking

Per the parity plan §8, a cell is ✅ only when **all** hold:
- native runtime works on that OS (no TODO/placeholder),
- a **clean full `orchestrate` run** is green on the real guest with the role's
  FAIL-LOUD live stage (§7) — not a dry-run substitute,
- the matrix row is in `live_lab_run_matrix.csv` (exact commit, correct per-cell status,
  node identity per role; verify it exists after every evidence run),
- the security controls for that role have an enforcement point **and** a verification
  test (incl. the negative path),
- `CrossPlatformRoleParityPlan_2026-06-21.md` §3 cell flipped to ✅ in the same change.

Rustynet is "cross-platform complete" only when **every** §3 cell is ✅ (or explicitly
🚫 out-of-scope-by-design with a recorded reason: Windows blind_exit; and 🔒 documented
external blockers: Windows exit WinNAT, relay forwarding HP-3).

---

## 11. Enabling tasks (small infra — do these alongside the cells)

1. **`flock` the run-matrix append** (`live_lab_run_matrix.rs:1528-1560`) — advisory lock
   on `documents/operations/live_lab_run_matrix.csv` (or a sidecar `.lock`). The only
   host-side hazard for concurrent runs. ~20 lines + a test. **Unblocks §8.3 fully.**
2. **Authored `CrossOsRoleSwitchPlan_2026-06-24.md`** (replaces the gitignored `state/` path the matrix cited) —
   the role-transition design (§4) that cell #4 depends on.
3. **Correct the §3 matrix** (the three corrections in §1): admin 🟡-ready (drop the stale
   "self-mint disabled"), Windows blind_exit 🚫 by-design, macOS blind_exit 🟡.
4. *(Optional)* a `--no-rebuild` alias for the empty-`--rebuild-nodes` keep-warm pass
   (`install.rs:134-138`) — first-class validate-only ergonomics.
5. *(Optional)* a second Debian exit-capable flag (via `--update-inventory-live-ips`) if
   the §8.3 first concurrent run shows the backbone requires it.
6. **Security-hardening adopt-items (Appendix A.3)** — the per-cell CONFIRM items are folded
   into each cell's spec; the genuine *new* additions (beyond current controls) are tracked
   here so they aren't lost: gossip/rumor-mill revocation propagation (#11), overlapping-trust
   window for owner-key rotation (#12), and distribution-layer default-deny / endpoint-info
   withholding (#13). These are security roadmap items (not blockers for the first cells); land
   them with the relay (HP-3) and revocation work they're closest to.

---

## 12. References
- `CrossPlatformRoleParityPlan_2026-06-21.md` — the release-blocking mandate, §3 matrix,
  §8 DoD (authoritative status; this roadmap operationalizes it).
- `LiveLabExecutionEfficiencyPlan_2026-06-20.md` — verified iteration primitives
  (setup/run split, per-node rebuild, single-stage wrappers); §8 here extends it to
  concurrency + per-role loops.
- `MasterWorkPlan_2026-03-22.md` — HP-3 (production relay transport; gates relay
  forwarding parity) and HP-2 (WAN simultaneous-open traversal).
- `AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md`,
  `AnchorNodeRoleDesign_2026-05-21.md` — anchor role context.
- `WindowsExitNodeRunbook_2026-06-04.md` — the WinNAT/`MSFT_NetNat` blocker for Windows exit.
- `documents/operations/live_lab_run_matrix.csv` — the evidence ledger; a row per run.
- MCP `get_role_transition` / `get_platform_support` — canonical per-OS role support +
  transition side-effects.

---

## Appendix A — Industry-grounded security hardening (mature mesh-VPN patterns)

The roadmap's cells must implement *industry-proven* logic, not novel invention — Rustynet
is Rust-first with **no custom crypto / no custom VPN protocol** in production paths, so
every control here is borrowed from a shipped project and cited. Verdicts: **CONFIRM** =
Rustynet already does this and industry validates it (keep it, add the test if missing);
**ADOPT** = a gap the mature projects say to close; **AVOID** = a risky divergence with a
safer proven alternative.

### A.1 Per-role / per-mechanism verdicts

- **Admin (centralized signer).** CONFIRM owner-public-key-as-trust-anchor + admin mints
  signed bundles (matches Tailscale's "coordination server is a drop box for public keys,
  never private", ZeroTier controller-signs-all-credentials, Nebula offline CA). **ADOPT:**
  (1) *signer-stamped freshness* — freshness/epoch is stamped by the signer, not the node's
  wall clock (ZeroTier "controller-populated timestamps… without trusting the node's local
  clock"), closing the clock-skew fail-open hole; (2) *mint-from-public-key-only* — admin
  mints a membership record from a node's **public key alone**; the node private key never
  transits (Nebula `nebula-cert sign -in-pub`; same invariant as client-side keygen below).
- **Anchor (enrollment + gossip + bundle-pull).** CONFIRM strongly — anchor is operational
  metadata, never a trust authority; anchor flags never consulted before signature verify;
  bundle-pull defaults to loopback (default-deny bind); HMAC secret in OS-secure custody;
  single-use enrollment-token ledger with fail-closed replay rejection. This *is* Nebula's
  "lighthouse holds no keys, cannot decrypt, cannot forge" containment, codified. **ADOPT:**
  (1) *control-plane-behind-the-tunnel* — bind steady-state bundle-pull to the mesh tunnel
  address (innernet: "API only on the in-tunnel internal IP — to attack it you must already
  be an enrolled peer"), reserving loopback+token for cold-start only; (2) *token carries
  scope* — the enrollment token encodes the target role/CIDR/group so redemption lands the
  node in the right default-deny scope (innernet CIDR / NetBird auto-group); (3) *revoke-
  token ≠ deauthorize-node* — a separate membership revocation (epoch bump); make it a
  negative test (Tailscale's explicit warning).
- **Relay (HP-3, the next big implementable).** **ADOPT as hard requirements:** (1) the
  load-bearing invariant **relay-never-sees-plaintext** + a **negative live test** that a
  relay cannot produce plaintext from a captured forwarded frame (Tailscale DERP "blindly
  forwards already-encrypted traffic", Firezone/NetBird TURN E2E-WireGuard, Nebula forwards
  Noise); (2) **no relay chaining** (Nebula "you cannot relay to a relay"); (3) **inbound
  rate-limit that closes — doesn't queue — and never throttles STUN/discovery** (DERP
  `accept-connection-limit`/`burst`); (4) **start-relayed → discover-direct-in-parallel →
  upgrade transparently** so sessions are usable instantly (Tailscale NAT-traversal); (5)
  **relay client auth against signed membership** (DERP "verify client owns its claimed key
  + is ACL-visible"; PSK only for relay↔relay mesh); (6) build as **sans-IO state machines**
  (Firezone `snownet` = `str0m` ICE + `boringtun`) so anti-replay/fallback/upgrade get
  deterministic time-travel tests with no sockets — directly serves CLAUDE §8 + the
  one-enforcement-point-one-test rule. Note: `client → relay` is fail-closed on macOS/Windows
  today, so test (1) is also the evidence gate that unblocks relay product-activation there.
- **Exit.** CONFIRM — deploy-before-advertise + NAT-teardown-before-capability-removal is
  Tailscale's exit-node **double opt-in** ("must opt in… Admin enables on the device AND in
  the console") plus a teardown-ordering guarantee Tailscale doesn't even document. Optional
  ADOPT: an autoApprovers-style **scoped** self-approval as explicit signed policy (never a
  blanket bypass).
- **blind_exit (irreversible).** CONFIRM — typed factory-reset ack + matrix-enforced
  irreversibility goes *beyond* industry in a good direction (closest analog: Tailscale
  tagged-identity replaces user identity). **ADOPT:** the fresh re-enrollment after wipe must
  route through the **same single-use, client-side-keygen, scoped token path** — mint a brand
  new device keypair locally, never reuse the old identity; negative test that the pre-reset
  key is wiped and unrecoverable.
- **Signed-bundle verify-before-apply.** CONFIRM exactly — signature → freshness/replay →
  apply is the universal ordering (ZeroTier, Nebula handshake, even WireGuard checks replay
  *after* AEAD auth). Only ADOPT: signer-stamped freshness (A.1 admin).
- **Anti-replay / rollback.** CONFIRM epoch monotonicity + replay-watermark. **ADOPT** an
  explicit **bounded-staleness rollback window** (ZeroTier COM moving-window: reject older
  than `current_epoch` OR older than `now − max_staleness`, signer-stamped) for graceful
  clock-skew while staying fail-closed; negative test: a re-served older-epoch bundle (incl.
  an anchor-downgrade) is rejected.
- **Key custody / rotation.** CONFIRM OS-secure custody (Keychain/DPAPI/encrypted-at-rest +
  perm checks, never log key material). **ADOPT:** (1) *key separation by concern* — control-
  identity key (stable) vs data-plane WireGuard key (rotatable/expirable) vs discovery key
  (Tailscale machine/node/disco split limits blast radius); (2) *rotate-by-replacement* —
  add-new-peer → propagate → drop-old-peer in the handshake idle gap, never in-place (WG has
  no in-place renew by design); (3) *expiry fails closed → re-enroll*, with explicit audited
  "disable expiry" only for unattended exit/anchor/relay/service nodes (Tailscale tagged-
  default-disabled).
- **Default-deny ACL.** CONFIRM structural default-deny (empty/missing/stale ⇒ Deny; rules
  with empty `contexts` never match; identity from the authenticated tunnel source, never a
  client header) — matches Tailscale's "only verb is accept", Nebula cert-bound groups,
  WireGuard cryptokey-routing. **ADOPT** *distribution-layer enforcement* (innernet: the
  membership snapshot served to a node contains only the peers/endpoints it may reach) — so
  default-deny holds even if a host firewall is bypassed, and metadata leakage is bounded.
- **Revocation (biggest gap).** **ADOPT:** (1) *gossip/rumor-mill revocation* over the anchor
  gossip surface so a kicked node is excluded even when the admin can't reach every peer
  (ZeroTier rumor-mill); (2) *overlapping-trust window* for owner-key rotation (Nebula
  concatenated-CA: trust old+new during a migration window, verify-against-any, then drop
  old) — no flag day; (3) codify token-revoke vs node-deauthorize (above).

### A.2 Risky divergences — avoid these

1. **Strict-monotonic epochs with no slack** → legitimate skew causes fail-closed lockouts,
   or a clock-trusting node is tricked. **Safer:** ZeroTier signer-stamped bounded-staleness
   window.
2. **No gossip revocation** → a revoked node stays reachable across a partition. **Safer:**
   rumor-mill propagation over the existing gossip surface.
3. **Bundle-pull on loopback+LAN-flag rather than in-tunnel** → broadens attack surface to
   the whole LAN. **Safer:** innernet in-tunnel API for steady-state.
4. **Any custom crypto / PoW-style identity hardening** → ZeroTier's v1 "memory-hard" PoW was
   shown *not* memory-hard and they migrated x25519→P-384. **Keep the no-custom-crypto rule;**
   ed25519 signed bundles + WireGuard Noise_IK only; if anti-squatting is ever needed, use a
   standard, versioned construction.
5. **Reusable enrollment tokens without a usage cap** → a leaked token = unbounded
   enrollment. **Safer:** single-use default; reusable only with usage-cap + expiry (NetBird).
6. **WireGuard adapter widening `AllowedIPs` or mutating keys in place** → too-broad allowed-
   IPs silently authorizes spoofed source IPs (breaks default-deny); in-place key mutation
   breaks anti-replay/forward-secrecy. **Safer:** narrowest allowed-IPs policy permits; rotate
   by full peer replacement; never disable the sliding window / mac2 cookie / handshake rate-
   limit; optional PSK is an additive hedge, never sole auth.

### A.3 Adopt-checklist (bake into the cells; ranked by where they land)

| # | Pattern | Source | Rustynet hook / cell |
|---|---|---|---|
| 1 | **Relay-never-sees-plaintext invariant + negative live test** | DERP, Firezone, NetBird, Nebula | HP-3 relay; new live assert (also unblocks mac/win relay) |
| 2 | No relay chaining | Nebula | HP-3 relay FSM |
| 3 | Inbound rate-limit (close, don't queue); never throttle STUN | DERP `derper.go` | HP-3 relay listener |
| 4 | Start-relayed → discover-direct-in-parallel → upgrade | Tailscale | HP-3 connectivity FSM |
| 5 | sans-IO state machines (deterministic time-travel tests) | Firezone `snownet`/`str0m` | relay + role-transition + trust transitions |
| 6 | Deploy-before-advertise / undeploy-before-revoke | Tailscale double opt-in | exit & relay cells (CONFIRM) |
| 7 | Capability never self-granted; admin approval gate | Tailscale | role-transition cell (CONFIRM) |
| 8 | Enrollment token: single-use default, client-side keygen, carries scope, bounded reuse+expiry | innernet, NetBird, Tailscale | anchor enrollment; extend token ledger with scope |
| 9 | Revoke-token ≠ deauthorize-node (separate paths + test) | Tailscale | enrollment + revocation |
| 10 | Signer-stamped freshness + bounded-staleness rollback window | ZeroTier COM moving-window | verify-before-apply + anti-replay |
| 11 | Gossip/rumor-mill revocation propagation | ZeroTier | anchor gossip surface (NEW) |
| 12 | Overlapping-trust window for owner-key rotation | Nebula multi-CA bundle | membership trust-root rotation (NEW) |
| 13 | Default-deny enforced at distribution (withhold endpoint info unless authorized) | innernet | membership snapshot scoping (NEW) |
| 14 | Key separation by concern; rotate-by-replacement; expiry fails closed → re-enroll | Tailscale + WireGuard | key custody/rotation; relevant to cross-OS transitions |
| 15 | Adapter preserves WireGuard invariants (narrow allowed-IPs, no in-place key mutation, keep sliding-window/mac2/rate-limit, PSK additive only) | WireGuard | backend adapter contract |

**Most relevant to the two next big implementables:** relay (HP-3) → items 1–5, with #1 the
non-negotiable; cross-OS role transitions → items 6, 7, 14 (Rustynet already encodes the
double-opt-in discipline; the gaps to add are key-expiry-fails-closed + re-enrollment, and
routing blind_exit re-enrollment through the single-use token path).

**Sources:** Tailscale (how-tailscale-works, how-nat-traversal-works, DERP `cmd/derper`,
key-management, exit-nodes, auth-keys, policy-file syntax, tags); WireGuard (protocol,
known-limitations, cryptokey-routing); Nebula (lighthouse/relay/firewall/CA-rotation docs);
ZeroTier (controller + protocol docs, COM moving-window); innernet (`tonarino/innernet`,
tonari blog); NetBird (how-it-works, setup-keys); Firezone (architecture, sans-IO blog,
`snownet`). New `(NEW)` hooks (#11–#13) are genuine roadmap additions beyond current controls.
