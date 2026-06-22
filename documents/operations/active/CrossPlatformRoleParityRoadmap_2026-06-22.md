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

- **What's left (mac/win):** of 7 roles × 2 OS, the genuine remaining work is **~7
  implementable cells + 1 design doc + 1 small infra fix**. Two cells are
  hard-blocked (Windows exit on the lab guest's missing WinNAT stack; relay live
  forwarding on the HP-3 transport item) and one is **out of scope by design**
  (Windows blind_exit). The rest is mostly *authoring live-lab stages that
  fail loud*, not new runtime code.
- **Ordered program (after the in-flight macOS anchor):** macOS admin → Windows
  admin → macOS blind_exit → cross-OS role transitions (needs a design doc first) →
  macOS relay *live lifecycle* (forwarding stays HP-3-gated) → Windows/macOS anchor
  live. Relay forwarding and Windows exit/blind_exit are explicitly parked with
  reasons.
- **Pipeline:** run a **Windows lab and a macOS lab simultaneously** on disjoint
  Debian backbones, iterate each role with **standalone SSH wrappers** against an
  already-warm guest (seconds, no 9-min bootstrap), and **write the next cell's code
  on `main` while both run**. One ~20-line `flock` on the run-matrix CSV is the only
  thing standing between us and fully-safe concurrency.
- **All on `main`:** the `orchestrate` command never re-validates HEAD mid-run, so
  committing to `main` during a run is safe. Use `--source-mode working-tree` to test
  uncommitted edits, commit after green. The node-map session lives on its own branch,
  so `main` is free for parity work. No feature branches required.

---

## 1. Where we are — the role × OS picture

Restated from `CrossPlatformRoleParityPlan_2026-06-21.md` §3 (legend: ✅ live-proven ·
🟡 implemented, not yet run green live · 🟠 contract/dry-run validator only · ❌
untested/not implemented · 🔒 blocked):

| Role | Linux | macOS | Windows |
|---|---|---|---|
| client | ✅ | ✅ | ✅ (active client traffic pending cross-OS run) |
| admin (mint/issue signed bundles) | ✅ | ❌ *(see §4 — "self-mint disabled" framing is **stale**, not a posture)* | ❌ (trust keygen works; live issuing untested) |
| anchor (gossip/bundle-pull/enrollment) | ✅ | 🟡→ landing now (live bundle-pull stage) | 🟠 dry-run plan contract only |
| exit (NAT egress + killswitch) | ✅ | 🟡 implemented — needs a green live run | 🟡 implemented but **🔒 lab guest lacks WinNAT/`MSFT_NetNat`** |
| blind_exit (irreversible exit) | ✅ | ❌ live stage missing — **runtime already exists** (`macos_blind_exit.rs`) | 🚫 **blocked by design** (`main.rs:11768` hard-errors; macOS/Linux only) |
| relay (live session forwarding) | ✅ *(lifecycle only — no live forwarding proof anywhere; see §4)* | 🟠 lifecycle dry-run | 🟠 SCM lifecycle contract only |
| live role transitions (cross-OS) | ✅ (`role_switch_matrix`) | ❌ | ❌ (banked design file is **missing**) |

**Three corrections this roadmap makes to the matrix (apply when landing each cell):**
1. macOS **admin** is in-scope and unblocked — the "self-mint deliberately disabled"
   note has **no backing** in code or `SecurityMinimumBar` (§4). Re-label as 🟡-ready.
2. **Windows blind_exit** is not a gap to close — it is an intentional platform
   exclusion (`main.rs:11768`). Re-label ❌ → 🚫 (out of scope, like mobile clients).
3. macOS **blind_exit** runtime already exists (`crates/rustynetd/src/macos_blind_exit.rs`,
   wired in `phase10.rs:2457,2653,2967`); only the live stage is missing → it's 🟡, not ❌.

---

## 2. Remaining work per role (mac/win) + effort

Effort is focused-engineering time *including* live iteration on the VM (live bugs only
surface live — the macOS anchor cell took 3 live runs to expose an SSH-user defect a
dry-run had masked). "Live stage" = author a fail-loud stage per §7.

| # | Cell | Status | What's needed | Effort | Gating |
|---|---|---|---|---|---|
| — | macOS anchor | 🟡 landing | confirm live (not dry-run-fallback) PASS, fold in fail-loud fix, push | in flight | — |
| 1 | **macOS admin** | ❌→ready | live stage only (issuing path is platform-neutral; keychain custody exists) | ~0.5–1 d | none |
| 2 | **Windows admin** | ❌→ready | live stage only (DPAPI custody exists) | ~0.5–1 d | none |
| 3 | **macOS blind_exit** | 🟡 (runtime exists) | live stage only, **run last** (wipes identity); disposable guest | ~0.5–1 d | none |
| 4 | **Role transitions (macOS→Windows)** | ❌ | **design doc first** (`state/cross_os_role_switch_plan.md` missing), then a stage that drives a real flip and re-applies signed state via `refresh_signed_state_with_reason` | ~2–4 d | needs admin (#1/#2) |
| 5 | macOS **exit** | 🟡 | just a green run with `--exit-platform macos` (no code) | ~hours | none |
| 6 | macOS **relay** *live lifecycle* | 🟠 | upgrade dry-run → live lifecycle (active/listener/healthz on guest). **Forwarding proof is separate.** | ~1 d | forwarding 🔒 HP-3 |
| 7 | Windows **anchor** live + macOS **anchor** live | 🟠/🟡 | convert in-process contract validators to live bundle-serving stages | ~1–2 d | sequence after anchor cell settles |
| 🔒 | Windows **relay** forwarding | 🟠 | nothing to author until a Linux live two-peer forwarding stage exists | — | **HP-3** (`MasterWorkPlan` HP-3 — "most substantial remaining code item"; weeks) |
| 🔒 | Windows **exit** | 🟡 | code done (`promote_windows_exit_active`); needs a WinNAT-capable guest | — | lab env (`MSFT_NetNat` absent) |
| 🚫 | Windows **blind_exit** | — | out of scope by design (`main.rs:11768`) | — | n/a |

**Bottom line:** ~6–10 focused days of implementable parity work (cells 1–7), gated
behind HP-3 only for *relay live forwarding* and behind a lab-env fix for *Windows exit*.
Plus ~1 day of small enabling infra (§8.3, §11).

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
check without serving a bundle; the Windows contract validators
(`validate_windows_anchor_bundle_pull_plan_contract` `:9516`,
`validate_windows_relay_service_lifecycle_contract` `:9565`) run entirely in-process
against repo files ("without guest mutation") — they never touch the guest. These are
the exact defects §7 forbids.

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
is pending. **Conclusion:** macOS/Windows relay *live forwarding* parity cannot be
authored until HP-3 lands a Linux two-peer forwarding stage; once that's green and a
`--relay-platform` selector points it at a mac/win relay, parity is a port. Until then,
upgrade the mac/win relay dry-run to a **live lifecycle** stage (strictly better than
today) and label it as lifecycle-not-forwarding.

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
`state/cross_os_role_switch_plan.md` **does not exist** (the matrix cites it as "banked"
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

Rank = value ÷ (tractability · safety). After **anchor (in flight)** and **macOS exit
(just a green `--exit-platform macos` run)**:

| # | Cell | Why this rank |
|---|---|---|
| 1 | **macOS admin** | closes a ❌ with a pure live-stage add, no new dataplane; framing-stale unblock |
| 2 | **Windows admin** | same platform-neutral issuing code; DPAPI custody exists |
| 3 | **macOS blind_exit** | runtime exists; only the live stage missing; safe on disposable guest; run last |
| 4 | **Role transitions (macOS→Windows)** | reuses `refresh_signed_state_with_reason`; depends on admin; needs design doc |
| 5 | **macOS relay live lifecycle** | upgrade dry-run→live now; forwarding stays HP-3-gated; label clearly |
| 6 | **Windows + macOS anchor live** | convert contract validators to live bundle-serving; sequence after anchor settles |
| 🔒 | Windows relay forwarding | blocked on HP-3 (no live forwarding proof anywhere) |
| 🔒 | Windows exit | blocked on WinNAT guest (code done) |
| 🚫 | Windows blind_exit | out of scope by design |

---

## 6. First three implementable cells — file-by-file

### Cell 1 — macOS admin (mint/issue signed bundle, live)
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

### Cell 2 — Windows admin (mint/issue signed bundle, live)
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

### Cell 3 — macOS blind_exit (irreversible exit, live, run last)
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
   delete/replace: `validate_macos_anchor_bundle_pull` (`8915-8961`), and the Windows
   contract validators (`9516`, `9565`) that never touch the guest.
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

The user constraint: **do all of this on `main`, not a feature branch.** This is safe and
clean because:

1. **`orchestrate` never re-validates HEAD mid-run.** The provenance check that emits
   "setup manifest git provenance mismatch" (`validate_setup_manifest`,
   `vm_lab/mod.rs:2584`) is called **only** from the `setup`/`run` split subcommands
   (`:2784`, `:5107`) — **never** from `orchestrate`. So committing to `main` during an
   `orchestrate` run cannot fail the run. **Rule: always use `orchestrate`; never the
   `setup`→`run` split for parity work.**
2. **`--source-mode working-tree` tests uncommitted edits.** It snapshots staged+unstaged
   *tracked* changes via `git stash create` at stage 2 (`source_archive.rs:52-68`) and
   ships that frozen tarball — so you edit role code on `main`, run the lab, validate
   live, then **commit only after green**, keeping `main` always-green by construction.
   (Untracked new files are *not* captured — `git add` them first, or they won't deploy;
   `what_will_deploy` shows this.)
3. **Commit freely mid-run.** Once stage 2 (`PrepareSourceArchive`) has run, the deployed
   tarball is frozen; later commits on `main` are invisible to the running lab.
4. **`main` is free.** The node-map session commits to
   `claude/rustynet-node-map-visual-mmclho`, not `main`, so its work never moves `main`'s
   HEAD. Parity dev and lab runs own `main`.

**Concrete loop, all on `main`:**
```
# (on main, in the lab-main worktree which tracks main)
edit cell code → cargo fmt + clippy -p <crate> + touched-crate tests
→ orchestrate ... --source-mode working-tree   # ships uncommitted edits, validates live
→ green? git add -A && git commit (Iwan-Teague, NO Co-Authored-By trailer) && push origin HEAD:main
→ next cell
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
2. **Recreate `state/cross_os_role_switch_plan.md`** (the matrix cites it; it's missing) —
   the role-transition design (§4) that cell #4 depends on.
3. **Correct the §3 matrix** (the three corrections in §1): admin 🟡-ready (drop the stale
   "self-mint disabled"), Windows blind_exit 🚫 by-design, macOS blind_exit 🟡.
4. *(Optional)* a `--no-rebuild` alias for the empty-`--rebuild-nodes` keep-warm pass
   (`install.rs:134-138`) — first-class validate-only ergonomics.
5. *(Optional)* a second Debian exit-capable flag (via `--update-inventory-live-ips`) if
   the §8.3 first concurrent run shows the backbone requires it.

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
