<!-- Produced by a ten-agent parallel classification of every VmGuestPlatform site in the
     vm-lab orchestrator, 2026-09-08. Measured, not extrapolated: 783 sites classified.
     UNTRUSTED - verify a site against the code before acting on it. -->

# Platform-Branching Audit — `crates/rustynet-cli/src/vm_lab/**`

**Date:** 2026-09-08 · **Scope:** every `VmGuestPlatform` site in the vm-lab orchestrator · **Question answered:** what does it cost to add an OS, and where does a new OS silently do the wrong thing?

**Verdict.** The branching surface is real but far smaller and far more concentrated than the earlier estimates suggested. 180 behaviour-branch sites, in 52 decision groups, in 4 remedy clusters that cover half of them. **48% of those groups (25 of 52, ~70 lines) silently take the Linux arm** — and that is not a future-OS hypothetical: `VmGuestPlatform` already has five variants, and `Ios`/`Android` already fall into every one of them today.

---

## 1. The real numbers

| Class | Sites | Share | Meaning |
|---|---:|---:|---|
| **test** | 380 | 49% | Inside `#[cfg(test)]`. Zero cost to a new OS. |
| **gate** | 156 | 20% | Named fail-closed capability predicates. **Correct as-is** — a new OS gets a loud, recorded skip. |
| **branch** | 180 | 23% | Per-OS *behaviour* selection. This is the migration. |
| **other** | 67 | 9% | Enum conversion, type positions, serialization, string parsing. |
| **Total** | **783** | | |

### Against the prior estimates — both were wrong, in opposite directions

- **"769 sites outside the adapter layer"** was roughly right as a *total* (783 measured) but wrong as a *problem statement*. 69% of it is tests and correct gates. Only 23% is the thing that needs work.
- **"~250 behaviour branches" (extrapolated)** overshot. The real figure is **180 — 28% lower**. Say 180, not 250.
- Caveat, stated plainly: the 180 is a **line count**, and auditors used two conventions (per grep-line vs. per logical decision). Reconstructing per-group line counts from the findings sums to **187**, a ~4% spread against the measured 180. All percentages below are taken against the 187 reconstruction so the columns sum to 100%; treat every figure as ±4%.

### What 180 means for the cost of adding an OS

Of the 52 branch decision groups:

| New-OS outcome | Groups | What the implementer experiences |
|---|---:|---|
| **Compile error** | 12 (23%) | Exhaustive `match platform`, no `_`. The compiler names the file and line. This is the target. |
| **Silently becomes Linux** | 25 (48%) | Compiles clean, runs the Linux command/path/user/port. No error, no skip record. |
| **Loud runtime failure** | 8 (15%) | Fails, but names the wrong cause (SSH, daemon, `tar`) instead of the missing per-OS entry. |
| **Cosmetic** | 7 (13%) | Wrong reason string, wrong operator hint. |

So today the answer to *"what does adding an OS cost?"* is: **you get 12 compile errors telling you where to work, and 25 places that compile clean and behave as Linux.** The migration's goal is to move the second column into the first.

**The mechanical rule that separates a gate from a branch, and it is worth adopting as a review check:**

> If you can add a variant to `VmGuestPlatform` and the file still compiles, that file is a branch site, not a gate site.

`capability.rs` passes that test at all 5 production sites. `network_audit.rs` fails it at 4 of 7.

---

## 2. Silent-wrong register — read this first

These 25 groups are the actual risk. A new OS (or `Ios`/`Android`, today) reaches them, produces a plausible-looking result, and nothing records that anything was skipped. Ordered by blast radius. `R#` cross-references the remedy in §3.

| # | Site | What silently happens | Remedy |
|---|---|---|---|
| 1 | `mod.rs:2020` — `else { Self::Linux }`, terminal arm of `VmGuestPlatform::infer` | **The root cause of the whole class.** Any alias/os_name/UTM name matching none of the windows\|macos\|ios\|android substrings is inferred Linux. Decides which variant every other match in the file then sees, so it makes downstream compile-time guarantees unreachable. Written `Self::`, so no `VmGuestPlatform::` grep surfaces it. | **R7** |
| 2 | `membership_init.rs:225`, `distribute_assignments.rs:82`, `native.rs:348,527,570,630` — `unwrap_or(VmGuestPlatform::Linux)` | An inventory entry that merely omits `platform` gets **Linux capabilities minted into the signed membership snapshot** (225, 82) and **passes a fail-closed role gate as Linux** (348, 570). Live-reachable: `InventoryEntry.platform` is `Option` and the loader leaves it `None` when the key is absent. Inverts §10.1/§10.4 at a trust-state boundary. | **R7** |
| 3 | `role_validation/blind_exit.rs:104` — `_ => {}` in the NAT-forwarding probe | Returns `Ok(())` having **proven nothing about NAT** on a blind_exit node. Latent only because `blind_exit_runtime_implemented` gates it — the moment anyone widens that gate to enable a new OS (the intended way to add one) the proof evaporates and the stage goes green. | **R9** |
| 4 | `role_validation/anchor.rs:515` — `if platform != Linux { return Ok("…skipped") }` | Drops the **token-redaction security assertion** (§4, never log secrets) for every non-Linux OS. The caller (`anchor_validation.rs:235`) tests only `if let Err(e)`, so the skip string is discarded: **no evidence trace at all** that a security control did not run. | **R9** |
| 5 | `mod.rs:30642` (`_ => true`) and `30566` | Readiness is declared on powered+networked alone for anything that is not Linux/macOS. A new OS is reported **READY with zero evidence anything on it is reachable**, and the restart/fail-loud path never fires. Fail-open and completely silent. | **R6** |
| 6 | `role_validation/relay.rs:262` — `relay_ports`, the file's only `_` arm | New OS silently inherits ports 4500/4501. Called at `relay.rs:161` *before* the first capture, so the wrong ports are baked into the failure text: a working relay reports `listener on :4500 was NOT bound` — **a real relay, a false failure, naming a port the OS never used.** Its three sibling dispatches *are* exhaustive, so the author is pushed to fix those and can land green having never seen this one. | **R9** |
| 7 | `mod.rs:26524` — grouped `Linux \| Macos` baseline probe | **macOS is already the new OS that fell into the Linux arm.** The shared arm hardcodes `systemctl is-active`, `journalctl`, `ip -4 route get`, `timedatectl`, `/run/rustynet/…`. On a Mac guest it collects `systemctl-unavailable` / `ip-unavailable` / `missing` for every state path — and the stage records those as **baseline evidence**. | **R9** |
| 8 | `network_audit.rs:1765` (`Some(Linux) \| None`) and `1821` (`_ =>`) | 1765 runs the iproute2 pipeline against a box with none of those binaries; 1821 parses the output with the Linux parser. Result is not a crash but an observation with empty interfaces / no default route / no DNS, which reads downstream as *"audited, nothing found"* rather than *"never audited"*. The `_` at 1821 also defeats the compile-time protection 1765 provides. | **R9** |
| 9 | `stage/{soak,two_hop,secrets,reboot,flap,custody,anchor,cross_network,chaos}.rs` + `live_managed_dns_validation.rs:175,265` — SSH-user `_` arms | Default login name. **Three mutually contradictory answers already exist** (`_ => "root"` ×6, `_ => "debian"` ×3, and `stage/mod.rs` matching only Windows so macOS also lands on "debian"). Symptom is an SSH auth failure attributed to the guest, never to the default. | **R1** |
| 10 | `soak:321-327`, `live_anchor:198-203` — `_ => "linux"` platform token | The token handed to an external validator binary, which keys its probes off it. A new-OS node is **labelled Linux to the validator**, runs Linux-shaped checks, and can report **PASS**. In soak the same arm swallows `None` (no adapter registered at all) as "linux". | **R2** |
| 11 | `exit_nat_lifecycle/exit_dns_failclosed/exit_demotion_residue/ipv6_leak/blind_exit_dataplane` `_validation.rs` — rustynetd path | Four of the five carry a `Macos` arm and then unconditionally call `validate_linux_*`. **The code reads as multi-platform**; widening a gate to macOS yields a GREEN stage running Linux nft/ip probes against a Mac. Three of the five use `_ => unreachable!("…desktop platforms only")` — a panic whose message is already false (the gate is `Linux\|Macos`). | **R3** |
| 12 | `preflight.rs:583` — `_` arm of `cross_bridge_probe_argv` | Runs `bash -c 'exec 3<>/dev/tcp/…'`. A guest without bash makes the probe non-zero, and `decide_cross_bridge` then **hard-fails the run asserting "guest-to-guest TCP/22 is blocked across the split"** and points the operator at CP-1 pf overrides. Nothing distinguishes "port blocked" from "probe binary absent": the stop is loud, the cause it names is fabricated. | **R10** |
| 13 | `role.rs:208,223,251` — guarded arms of `product_capabilities_for_platform` | A guarded match never covers an unlisted platform, so a new OS falls to `_ => match self`. This is the **signed-membership capability set** — what the node advertises in trust state. | **R8** |
| 14 | `mod.rs:30966`, `31031` | Any target given as a raw `user@host` (not an inventory alias) is hardcoded to `default_platform_profile(Linux)`. A raw-target macOS or Windows host is driven **end-to-end with the Linux profile** — Linux src dir, Linux temp dir, bash scripts — with no warning. | **R7** |
| 15 | `mod.rs:30287` — `if phase == SyncSource && platform != Windows { continue }` | A new OS **never syncs source**. Build/install then run against whatever happens to already be on the guest: a stale-source pass that looks green. | **R5** |
| 16 | `executor.rs:552-556` | Every overnight-march cell, on every platform, is orchestrated against a **hardcoded Linux exit + Linux client**. A new-OS cell is marked verified on evidence that never exercised a same-OS peer; a same-OS topology is unreachable through this path. Not a `_` arm — a literal constant, so adding a variant produces no error. | **R11** |
| 17 | `mod.rs:7272,7291,7392` | 7392 is the consequential one: readiness comes from `execution_ready` on Windows but from the SSH predicate elsewhere, so **discovery reports "ready" for a node the orchestrator cannot drive**. | **R6** |
| 18 | `mod.rs:3019` — `entry.platform.unwrap_or(Linux)` in `diagnose` | Bypasses `effective_platform_profile` entirely, so an entry omitting `platform` gets the Linux adapter **even when its alias literally says windows**. | **R7** |
| 19 | `mod.rs:7873` | Post-start access bootstrap simply does not fire for non-Windows, and nothing notes that it was skipped. Fails later at the first SSH dispatch, blaming SSH. | **R5** |
| 20 | `membership_init.rs:71-81,165` | The F1 owner-signing-key probe is skipped for every non-macOS node and the stage still passes. `165` hardcodes `product_capabilities_for_platform(&Macos)` rather than the node's platform, so the helper cannot be reused. **`NodeAdapter::probe_membership_owner_signing_key_present()` already exists** (`adapter/node_adapter.rs:188`) with a fail-closed default — this branch is redundant. | **R12** |
| 21 | `membership_init.rs:240-247` | A new OS reporting `GossipIdentity::DeferredPlatform` **joins signed membership with no gossip identity** — no error, no skip record, green stage. | **R12** |
| 22 | `native.rs:733-739` — `wants_macos` / `wants_windows` bools | A new-OS guest contributes to no `wants_*`, so its stages are **never planned — and therefore never skipped either**: no named skip, no evidence row, a silently narrower plan the finalizer accepts as complete. | **R11** |
| 23 | `live_mixed_topology_validation.rs:36-64` | The gate asks only whether Linux+macOS+Windows are present, so a topology containing a new OS satisfies it and the stage **reports PASS on a "mixed topology" proof that never touched the new guest**. | **R11** |
| 24 | `mod.rs:8901` | `ssh-auth-not-ready` reason code is emitted only for `Linux\|Macos`; other platforms get the generic `not-execution-ready`. Diagnostic only — but it degrades exactly the message an operator bringing up a new OS depends on. | **R6** |

**One loud-failure that is already live and belongs here anyway:** `role.rs:334` — `product_capabilities_for_platform` **panics today** on Windows + `blind_exit`. The Windows guard at 223 is `matches!(self, NodeRole::Exit)` only, so BlindExit falls to `_ => match self` and hits `unreachable!("handled above")`. It is reachable: `is_lab_assignable_for_platform` returns true for Windows for every non-Custom role, and `native.rs:347-362` gates solely on that predicate before calling it. So `--node <windows-alias>:blind_exit` panics inside plan validation, while `daemon_node_role_for_platform` happily returns `Ok("blind_exit")` for the same pair. **No test covers it** — the only Windows capability test uses `NodeRole::Entry`. Fix under **R8**; it is a §10.2 violation (panic in a production path) regardless of the migration.

---

## 3. The capability table — grouped by remedy

Each row is one adapter method or one per-OS data field. Adopt a row and the sites in it stop existing.

| ID | Method / data to add | Sites absorbed | Lines | % of branch |
|---|---|---|---:|---:|
| **R1** | `NodeAdapter::default_ssh_user(&self) -> &str` | 6 groups | 38 | **20%** |
| **R3** | `InstallLayout` per-OS record → `daemon_binary_path`, `rustynet_program`, `daemon_socket_path`, `relay_binary_name`, `membership_snapshot/log`, `anchor_token` | 7 groups | 29 | **16%** |
| **R4** | Filesystem-layout accessors: `rustynet_src_dir`, `remote_temp_dir`, `utm_staging_dir`, `orchestration_scratch_root`, `path_style` | 3 groups | 26 | **14%** |
| **R9** | Per-role validation probes on the adapter (8 methods) | 10 groups | 26 | **14%** |
| **R5** | Transport + bootstrap adapter: `exec`, `capture`, `push_file`, `ssh_fallback_allowed`, `repo_sync_dispatch`, `sync_source_archive`, `bootstrap_phases`, `post_start_access_bootstrap` | 5 groups | 22 | **12%** |
| **R7** | *Not adapter surface* — fail-closed platform resolution | 4 groups | 10 | **5%** |
| **R11** | Plan/topology as data | 3 groups | 8 | **4%** |
| **R6** | Readiness adapter | 4 groups | 7 | **4%** |
| **R8** | Role/capability matrix as data | 3 groups | 6 | **3%** |
| **R2** | Use the `as_str` that already exists | 1 group | 4 | **2%** |
| **R10** | Preflight probe argv | 3 groups | 4 | **2%** |
| **R13** | Relocate `default_platform_profile` onto the trait | 1 group | 4 | **2%** |
| **R12** | Capability-table booleans | 2 groups | 3 | **2%** |
| | **Total** | **52** | **187** | **100%** |

---

### R1 — `NodeAdapter::default_ssh_user(&self) -> &str` — 20%

> *The default SSH login name when the inventory supplies none. One method, six call sites, three currently-contradictory answers reconciled.*

| Site | Today |
|---|---|
| `stage/{live_extended_soak_validation:345, live_two_hop_validation:252, live_secrets_not_in_logs_validation:120, live_reboot_recovery_validation:145, live_network_flap_validation:152, live_key_custody_validation:123, live_anchor:191, cross_network:1444, chaos:233, mod:24}.rs` | 10 verbatim copies, 25 lines |
| `stage/live_managed_dns_validation.rs:175-181`, `:265-272` | duplicated within one file; the second bakes the wrong user into every `--managed-peer` argument |
| `mod.rs:28982` | `Windows => "Administrator", _ => "user"` |
| `mod.rs:30498-30502` | advisory string, `Linux => "debian@…"` |
| `mod.rs:7189` | discovery default, plus a note hardcoding the word "windows" |

The adapter **already owns `ssh_connection_params()`**; every one of these is the fallback for that same call, so the fallback belongs behind the same trait. `stage/mod.rs:12-18` documents the drift as deliberate ("preserves the LAN-toggle stage's historical values rather than unifying") — that comment is the licence the drift has been living under, and it goes with the branches.

**Start here.** Highest share, zero behaviour risk, and it forces a decision that is currently made three different ways.

---

### R3 — `InstallLayout`: one per-OS record for every on-guest path — 16%

> *Where the binaries and state live on each OS. Today the same question is answered in at least five places with at least two different answers.*

| Site | Today |
|---|---|
| `stage/{exit_nat_lifecycle,exit_dns_failclosed,exit_demotion_residue,ipv6_leak,blind_exit_dataplane}_validation.rs` | 5 copies of the rustynetd-path match; 3 use `_ => unreachable!` |
| `stage/security_audit_validation.rs:102-104` | a sixth copy, this one fail-closed (reported-skip) |
| `role_validation/blind_exit.rs:17` (`rustynet_program`), `:31` (`daemon_socket_path`) | both `_`-catch-all to the POSIX answer; both `pub(crate)` and called from `macos_reboot_recovery_validation.rs:307-312` **outside** any blind_exit gate |
| `role_validation/anchor.rs:109,114,119` | the `(program, membership snapshot, membership log)` triple |
| `role_validation/anchor.rs:366-368` | anchor bundle-pull token path — a *second* match re-deriving the same layout |
| `stage/live_hello_limiter_flood_validation.rs:52-60` | `rustynet-relay` vs `.exe`; the Linux and macOS arms are byte-identical, the tell that this is data |

**Measured duplication, not asserted:** `grep -c WINDOWS_RUSTYNETD_PATH crates/rustynet-cli/src/` → **23 references** across six stage files that each re-declare a private const, while the canonical values already sit in `adapter/{linux,macos,windows}_install.rs`. And `grep 'fn daemon_socket_path'` → **five separate definitions** in the CLI crate (`main.rs` ×2 cfg-split, `live_linux_lan_toggle_test.rs:1388` returning `None` for Windows, `live_lab_bin_support/mod.rs:1454` string-keyed, `role_validation/blind_exit.rs:29` handing Windows the *Linux* path). **They disagree.** Only the dispatch leaked out of the adapter layer; the data is already there.

---

### R4 — Filesystem-layout accessors — 14%

> `rustynet_src_dir(ssh_user)`, `remote_temp_dir()`, `utm_staging_dir(ssh_user)`, `orchestration_scratch_root(&target)`, `path_style`

| Site | Today |
|---|---|
| `mod.rs:2197-2246` (15 sites, 3 functions) | repo checkout root / scratch dir / utmctl staging dir. Exhaustive — a new variant is a clean 3-site compile error |
| `mod.rs:35774-35788` (10 sites, 2 near-identical functions) | scp path-separator normalisation. Pure data expressed as control flow, duplicated |
| `mod.rs:35843` | `windows_orchestration_root` — the SYSTEM-ACE carve-out |

These are the **clearest candidates in the file**: pure per-OS data, no logic. Today a new-OS author must find three free functions by grep. Residual hazard to preserve when moving them: the grouped `Linux | Macos | Ios | Android => None` arm at 2243 means a new POSIX-ish OS added there by reflex silently inherits "utmctl staging == remote_temp_dir", which the doc comment above it says is only safe when the guest agent and SSH user share an identity surface.

---

### R9 — Per-role validation probes on the adapter — 14%, and the highest security value

> *Eight methods. Contains four of the top six silent-wrong entries, including both fail-opens.*

| Method | Absorbs |
|---|---|
| `probe_nat_forwarding_rules(&self, shell) -> Result<NatRuleEvidence, String>` | `blind_exit.rs:69,80,97` + the `_ => {}` fail-open at 104 |
| `daemon_log_since(&self, shell, unit, since) -> Result<String, String>` | `anchor.rs:515` — journalctl / `log show` / `Get-WinEvent`. Absence of a log surface must be a capability `false` surfaced as a **recorded `Skipped`**, never an `Ok` the caller discards |
| `relay_listener_ports(&self) -> (u16, u16)` | `relay.rs:262` — no default row, so an OS with no entry is a missing-entry error |
| `capture_relay_lifecycle_snapshot(&self, shell) -> Result<RelayLifecycleSnapshot, String>` | `relay.rs:132-135`. **Seam is half-built** — `RelayLifecycleSnapshot` already normalises systemd/launchd/SCM state words; the three `capture_*_snapshot` fns move to their adapters unchanged |
| `start_relay_service` / `stop_relay_service` | `relay.rs:509-512`, `523-526`. Keep the readiness wait in the *shared* validator, not the impls — hoisting it per-OS would let a new adapter forget it and reintroduce the 2026-09-05 macos-utm-1 race |
| `validate_exit_nat_lifecycle(&self) -> Result<(), String>` | `exit_nat_lifecycle_validation.rs:81-88`. **The archetype**: the function already holds the adapter and calls `adapter.shell_host()`, `.start_daemon()`, `.activate_exit_serving()`, `.assert_exit_actively_serving()` in the same block — then steps outside it to pick the validator by platform |
| `network_observation_command()` + `parse_network_observation()` | `network_audit.rs:1765`, `1821`. **Keep them on the same object** — they are one contract about a text format, and splitting them across two matches is how the `_` arm at 1821 became possible |
| `baseline_runtime_probe_sections() -> Vec<(&'static str, String)>` | `mod.rs:26524`. macOS needs launchctl/scutil/`route -n get`/`/usr/local/var/rustynet` equivalents it does not have today |

**Independently of the trait work, and immediately:** delete `blind_exit.rs:104`'s `_ => {}` and `relay.rs:262`'s `_` arm. Both are one-line changes that convert a silent fail-open into a compile error.

---

### R5 — Transport + bootstrap adapter — 12%

| Method | Absorbs |
|---|---|
| `exec` / `capture` / `push_file` / `ssh_fallback_allowed(phase)` | `mod.rs:34470-34836` — 14 sites, **3 near-identical dispatches**. Exhaustive today (compile-safe) but triplicated |
| `repo_sync_dispatch(&self, mode)` | `mod.rs:8244-8259`. `RepoSyncDispatchKind` already exists — one method away from adapter-owned |
| `sync_source_archive(&self, archive, dest)` + `SourceArchiveFormat::{Tar,Zip}` | `mod.rs:33691` — the ~70-line Windows ZIP path vs the implicit POSIX/tar else |
| `bootstrap_phases(&self) -> &[BootstrapPhase]` | `mod.rs:30287` — the silent SyncSource skip |
| `post_start_access_bootstrap(&self, …) -> Result<Option<String>, String>` (default `Ok(None)`) | `mod.rs:7873` |

**The seam already exists in this file.** `RuntimePaths` + `runtime_paths_for(platform) -> Box<dyn RuntimePaths>` (`mod.rs:9737`), with a "W3.2 ServiceManager adapter" section immediately below, and `UnsupportedRuntimePaths` already models "this OS is not defined yet" as a loud blocker string rather than a default. Dispatch these the same way.

---

### R7 — Fail-closed platform resolution *(not adapter surface)* — 5%

> *Ten one-line changes. Do these first regardless of everything else — they are what make every other remedy's compile-time guarantee reachable.*

| Site | Fix |
|---|---|
| `mod.rs:2020` | `infer` returns `Option<Self>` (or add `Unknown`); both callers (2177, 7157) fail closed with *"cannot infer platform for alias X; set `platform` explicitly"*. `VmGuestPlatform::parse` at 1970 **already does this correctly** — `infer` is the inconsistent twin |
| `membership_init:225`, `distribute_assignments:82`, `native:348,527,570,630` | `ok_or_else(\|\| format!("'{alias}': no platform recorded; refusing to assume Linux"))?` — all six already sit in `-> Result` context |
| `mod.rs:3019` | call `effective_platform_profile(...)` like the rest of the file |
| `mod.rs:30966`, `31031` | require an explicit `--platform` with a raw target, or return a profile whose `remote_shell` is `Unsupported` so the existing error arms fire |

Note the payoff: `default_platform_profile` (R13) and the three filesystem tables (R4) are *already* exhaustive compile-error sites. They are unreachable as guarantees because `infer` coerces unknown OSes to Linux before they are consulted. **Fixing 2020 converts existing dead safety into live safety at no cost.**

---

### R2 — Use the `as_str` that already exists — 2%

**Correcting an auditor claim, verified against the tree:** `VmGuestPlatform::as_str` **does exist** at `mod.rs:2024`, is total over all five variants, and has 40+ callers including from descendant modules (`orchestrator/resolved_plan.rs:378`, `topology.rs:458`). It is reachable from every stage file today.

So the duplicated mappings at `soak:321-327`, `live_anchor:198-203`, `live_lan_toggle_validation:225-230` and `live_managed_dns_validation:192-198` are **not filling an absence — they are overriding a correct helper with a wrong one.** `as_str` returns `"ios"`/`"android"`; the copies return `"linux"`. Delete the copies and call the helper. This is the cheapest fix in the document.

---

### R6 — Readiness adapter — 4%

`readiness_requires_ssh(&self) -> bool` **defaulting to `true` (fail closed)** absorbs `mod.rs:30642`/`30566`; `discovery_readiness()` and `discovery_known_hosts_state()` absorb `7272`/`7291`/`7392`; `readiness_reason_codes(&ReadinessProbes)` with the generic list as the trait default absorbs `28527`; a `readiness_requires_ssh_auth: bool` profile field absorbs `8901`. The Windows exemption then has to be **declared** rather than inherited by everything that is not Linux/macOS.

---

### R8 — Role/capability matrix as data — 3%

| Site | Fix |
|---|---|
| `role.rs:135,159` | `daemon_role_for(&self, role)`. Exactly **one row varies** — macOS Exit maps to `blind_exit`, everything else matches — so the table is one field wide: `exit_daemon_posture: DaemonRole`. That also makes a security-relevant divergence auditable at a glance instead of buried in a 24-line DECREE comment |
| `role.rs:208,223,251` | `product_capabilities_for(&self, role)`, shared default for the platform-independent roles (the code already comments them as such at 306/322), each adapter overriding only its Exit/BlindExit row. The pf-blind-exit vs nft-admin-owner divergence is **irreducible** — it belongs on the adapter, it just must not be an inline match |
| `role.rs:260`/`334` | Delete the `_` arm; replace `unreachable!` with a fail-closed `Err`; tighten the Windows guard to `Exit \| BlindExit` returning explicit `Err` for BlindExit. **This is the live panic** — ship it independently of the migration |

---

### R10 · R11 · R12 · R13 — the remainder

- **R10** (`preflight.rs`, 2%): `probe_tcp(ip, port) -> Result<bool, AdapterError>` (**not** just `tcp_probe_argv` — keeping "refused" and "could not probe" as separate verdicts is the whole point), `set_clock(unix_seconds)`, `remote_unix_time()`. All 4 production sites in that file are branch defects; there are no gates and no `other`.
- **R11** (4%): `wants: BTreeSet<VmGuestPlatform>` replacing the two hardcoded bools (`native.rs:733`); `required_support_peers(role)` replacing the literal Linux exit+client array (`executor.rs:552`); the mixed-topology matrix derived from `VmGuestPlatform::ALL` so an unrepresented platform forces a **named skip instead of a green pass**.
- **R12** (2%): `membership_init:71-81` is a **redundant branch — just delete the `== Macos` test**, because `NodeAdapter::probe_membership_owner_signing_key_present()` already exists with a fail-closed default. `mints_gossip_identity_at_install() -> bool` absorbs `240-247`; the inline comment there already states the reasoning as a capability fact and then encodes it as an `==`.
- **R13** (2%): move `default_platform_profile` (`mod.rs:2141-2159`) onto the trait as `default_profile() -> VmPlatformProfile`, so "implement the adapter" is the single place a new OS declares its shell/exec/service triple. Also fix `ensure_live_lab_profile_desktop_orchestrator_supported` (27594-27639) to compare against `default_platform_profile(profile.platform)` rather than the hand-copied duplicate triple it asserts today — two tables, one truth.

---

## 4. Migration shortlist

Ordered by share-per-unit-of-work. Percentages are of the 187-line branch reconstruction.

| Order | Item | Removes | Cumulative | Why this order |
|---|---|---:|---:|---|
| **0** | **R7 — fail-closed resolution** | **5%** | 5% | ~10 one-line changes, no new types. Kills the #1 and #2 silent-wrong entries and makes R4/R13's *existing* compile-time guarantees actually reachable. Everything else is worth less until this lands. |
| **1** | **R1 — `default_ssh_user()`** | **20%** | 25% | One method. Largest single share in the audit. Reconciles three contradictory answers that exist today. |
| **2** | **R3 — `InstallLayout` record** | **16%** | 41% | One per-OS data record. Also deletes 23 duplicate const references and collapses five disagreeing `daemon_socket_path` definitions. |
| **3** | **R4 — filesystem accessors** | **14%** | **55%** | Three accessors over pure data. No behaviour risk. |
| **4** | **R9 — per-role probes** | **14%** | 69% | Eight methods, most work of the five — but it holds four of the top six silent-wrong entries and **both fail-opens**. If security ranks above line count, promote this to position 1. |

**Headline: R7 + R1 + R3 + R4 = 55% of all branch sites, for one trait method, one data record, three accessors, and ten one-line fail-closed fixes.** None of the four changes any behaviour on an existing OS.

**Ship independently, today, regardless of the migration** (each is a standalone defect, not adapter work):
1. `role.rs:334` — the live Windows+`blind_exit` panic (§10.2 violation, untested, reachable via `--node <win>:blind_exit`).
2. `blind_exit.rs:104` — delete `_ => {}`; a fail-open NAT proof one gate-widening away from going live.
3. `relay.rs:262` — delete the `_` arm; false relay failures naming a port the OS never used.
4. `security_audit_validation.rs:144-155` — `outcome_for` contradicts its own doc comment: one unsupported-OS node downgrades the **whole stage** to `Skipped("no node executed this validation")`, erasing the passing nodes' security evidence. Untested (the three tests cover no-skips, skips-only, failure-with-skips — never mixed pass+skip).
5. Six fail-open **gates** found while classifying, all one-line polarity flips: `backlog.rs:96` (deny-list — a brand-new OS's admin cell is typed `Unbuilt` at `base_value 90`, the *highest* scheduler priority, and goes to the top of the overnight march queue); `mod.rs:8096` (the only deny-list gate of 77 — a new OS is implicitly *allowed* into repo sync); `mod.rs:3472` (`| None` lets a platform-less entry into an apt-only path); `mod.rs:13843`/`13918` (`unwrap_or(Linux)` inside the relay-forward eligibility filter); `mod.rs:34444` (`ssh_fallback_allowed_for_target` — true for everything except Windows-during-AccessEstablishment); `admin_issue.rs:4` (`_platform` ignored, returns `true` — claims live admin-issue validation on Ios/Android; its own test only asserts the three desktop OSes).

**Copy these shapes.** The good patterns are in-tree and need no invention: `capability.rs:193-320` (the `evaluate_*` family — exhaustive, returns `(status, reason_code, message)`, and `evaluate_bootstrap_phase` shows the right rule: wildcards on the non-OS axis are fine, a wildcard on the OS axis is the defect); `host_cross_build.rs:93-113` (`target_triple` — exhaustive `match (platform, arch)`, unsupported combinations as explicit `Err` arms carrying a reason); `connection.rs:154-164` (transport×platform allowlist, the only site treating Ios/Android as real); `scenario/mod.rs` `AdmissionContract` (**`required_platforms` as data compared in a loop — no per-OS code path exists at all**, which is why all six of its `VmGuestPlatform` sites are in tests); the `*_runtime_implemented` allow-list family (positive allowlist → new OS is `false` → named, on-disk reported-skip). And quote `security_audit_validation.rs:180-190`'s comment in the ledger — it is the clearest statement of this audit's thesis anyone has written: a `_` arm *"would silently merge a newly supported platform into the LINUX columns, contaminating one platform's evidence with another's and producing no error. Adding a variant must break this match instead."*

**Do not convert any `*_runtime_implemented` gate into a negative test** (`!matches!(platform, Ios | Android)`). That inverts the default and a new OS would be silently claimed as supported. If they become a table, that table needs a per-cell reason field or the rationale in `gossip_convergence.rs:33` and `security_audit.rs:100` — which name *why* the gate exists and *which platform has actually executed the stage* — is lost.

---

## 5. Coverage and limits

### What was covered

`mod.rs` (54,288 lines, 230 sites) was split at the midpoint: 978–27639 and 27243–EOF. **The halves overlap at the seam rather than gapping it.** Both auditors read the enclosing function for every production site; nothing was classified from a grep line. Test-module boundaries were verified per file (first column-0 `}`), not assumed.

All other assigned files report 100% coverage. One auditor listed seven high-count stage files as "NOT REACHED (assigned to others)" — `host_cross_build`, `preflight`, `security_audit_validation`, `live_lan_toggle_validation`, `live_managed_dns_validation`, `negative_control`, `anchor_validation`, 88 sites. **Those were in fact covered**, by two other auditors (49 + 46 sites, every one read in context). **No file in scope is unclassified.**

### Four real gaps

1. **`Self::`-qualified variants are invisible to the audit's grep.** `mod.rs:2020` — the single most dangerous line found — is written `Self::Linux`, not `VmGuestPlatform::Linux`. Re-grepped for this report: **26 `Self::(Linux|Macos|Windows|Ios|Android)` hits** in `vm_lab/`, all inside the enums' own impl blocks (`parse`, `infer`, `as_str`). Confirmed benign apart from 2020, but no auditor's grep would have caught them. **Add `Self::` to the pattern before declaring the count final.**
2. **String-keyed per-OS decisions are outside the count entirely.** Verified: `network_audit.rs:1719` and `network_prepare.rs:1795` (`std::env::consts::OS == "macos"`, else-arm runs iproute2 that a new *host* OS does not have); `host_cross_build.rs:151-153` (`triple.contains("-linux-")` chooses `cargo build` vs `cargo zigbuild` — fail-closed, but a **second uncoordinated per-OS table the compiler cannot cross-check against `target_triple`**); `backlog.rs:315-322` `platform_from_str` (a divergent second parser accepting only the five canonical names, so a variant added to `VmGuestPlatform::parse` is unparseable from `--seed-status`); `live_lab_bin_support/mod.rs:1454` `daemon_socket_path_for_platform(&str)`. Small in count, invisible to the method.
3. **Scope was `vm_lab/**` only.** The shipped product crates — `rustynetd`, `rustynet-backend-*`, `rustynet-windows-native` — were not audited. Their `#[cfg(target_os)]` surface is a separate count and a separate document. **This audit says nothing about the product's own platform branching.**
4. **The 380 test sites were counted, not analysed.** That gap is load-bearing: the live Windows+`blind_exit` panic survived because no test calls `product_capabilities_for_platform` with that pair. Per-OS *test* coverage was not assessed and should be its own pass.

### Is the conclusion safe?

**Yes for the direction, and yes for the work plan.** Every remedy above is grounded in a function that was read, not a grep line inferred. The four shortlist items are data moves with no behaviour change on any existing OS, and the five standalone defects were each confirmed reachable through a named caller.

**No for the number as a ceiling.** 180 is a **floor**. Gaps 1 and 2 can only add sites, never remove them, and gap 3 is an entirely unmeasured surface. Cite 180 as "measured branch sites in `vm_lab`", never as "the total platform-branching surface of Rustynet".

**One structural caveat that outlives the migration.** `VmGuestPlatform::parse` folds `debian|ubuntu|fedora|mint` into `Linux`, so "new OS" has two meanings here. A new *enum variant* gets the compile-error analysis above. A new *Linux distro* is invisible to every site in this document and silently inherits the Linux arm — which is exactly how the Rocky `sudo secure_path` problem documented at `anchor.rs:96-106` arose. **No adapter method in this plan addresses that**, and none can; it needs distro-level capability data, which is out of scope here and worth a follow-up.
