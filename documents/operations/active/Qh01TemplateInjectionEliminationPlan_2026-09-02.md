# QH-01 (Phase 2) — Template-Injection Elimination in the Adapter Layer

**Status:** plan (docs-only; this document changes no code).
**Date:** 2026-09-02.
**Owning ledger:** `documents/operations/active/QualityHardeningTodo_2026-07-25.md`, QH-01 entry (`## P1 — Do these first`, :53-100), including the **[REVIEW 2026-07-25]** block ("Mechanism VERIFIED in every particular. Two corrections, and the proposed fix framing was INSUFFICIENT.").
**Predecessor plan:** `documents/operations/active/QH01TemplateInjectionFixPlan_2026-07-25.md` — its template-rendering half is EXECUTED and INTEGRATED on main (commit `0aff3c07` "route every host-script render site through the renderer"; renderer: `crates/rustynet-cli/src/vm_lab/script_template.rs`, 3369 lines).
**Scope of THIS plan:** the remaining raw template-construction class in the orchestrator adapter layer — `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/` — where scripts are built by `format!` and passed as raw `&str` into the `run_remote` / `run_remote_ps` SSH sinks. All file:line anchors below were read in this worktree; items that could not be confirmed are marked UNVERIFIED.

## 1) Inventory of template-construction sites

The sink family: `ssh::run_remote(conn, script: &str, timeout)` (`adapter/ssh.rs:432`), siblings `run_remote_with_log` (:442), `run_remote_retrying` (:495, idempotent read-only probes only), `run_remote_check` (:524); all lower to `cmd.arg(script)` in `run_remote_inner` (:456). The Windows PowerShell family: `windows_install.rs` `encode_ps_command` (:83, UTF-16LE+base64, rejects NUL) → `build_ps_invocation` (:96, `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}`) → `run_remote_ps` (:122) / `run_remote_ps_check` (:132) → `ssh::run_remote`. Per-file sink call-line counts (grep, this worktree): linux.rs 2, linux_install.rs 13, linux_membership.rs 6, linux_traffic.rs 32, macos.rs 2, macos_install.rs 15, macos_membership.rs 8, macos_traffic.rs 21, windows.rs 2, windows_install.rs 25, windows_membership.rs 7, windows_traffic.rs 23, ssh.rs 8 (definitions) — ≈164 call lines, all inside `vm_lab/orchestrator/adapter/`.

| Site(s) | Runtime values interpolated | Quoting helper | OS / shell dialect | Value provenance | Verdict |
| --- | --- | --- | --- | --- | --- |
| `adapter/linux.rs:209` `format!("sudo -n {}", argv.join(" "))` → `run_remote` :211; same shape `adapter/macos.rs:217` → :218; `adapter/windows.rs` (argv-join variant) | argv elements (subcommand, flags, paths) | none — bare space-join | linux (POSIX sh), macos (zsh), windows (cmd/PS) | internally constructed argv, but no validator at the seam | **UNQUOTED-RISK** — safe only by the unstated invariant that every element is constructed, not operator text |
| `adapter/linux_install.rs` (13 lines), `linux_membership.rs` (6) | paths, service names, node ids, bundle paths | per-site quoting, no shared seam | linux / POSIX sh | operator/inventory-controlled | **QUOTED** — escaping present but by per-site discipline; correctness rests on each author remembering |
| `adapter/linux_traffic.rs` (32 lines) | peer mesh IPs, ports | `validate_ip_arg` (:1036, with `rejects_injection` test :1615) + per-site quoting | linux / POSIX sh | guest-observed (traffic probes against other members) | **QUOTED** — validated at the value level, but the validator is file-local (triplicated, see below) |
| `adapter/macos_install.rs` (15), `macos_membership.rs` (8) | paths, utun names, launchd labels, node ids | `validate_utun_name` (`macos_install.rs:692`, test :1912) + per-site quoting | macos / zsh | operator/inventory-controlled | **QUOTED** — per-site |
| `adapter/macos_traffic.rs` (21) | mesh IPs, temp paths | `validate_ip_arg` (:659, tests :956/:962/:968) + hand single-quotes; e.g. ping `format!("ping -c 3 -W 1000 '{peer_mesh_ip}' 2>&1")` :351 guarded :350; BUT `run_remote(conn, &format!("rm -f '{remote_tmp}'"), …)` :419 hand-quoted with no validator shown at the site | macos / zsh | guest-observed | **QUOTED (partial)** — :419 is the weakest *guarded* site, not the weakest *exposed* one: `remote_tmp` is the compile-time const `/tmp/rn_diag_artifacts.tar.gz` (`macos_traffic.rs:398`), so there is no live injection today; the risk is regressive (a future parameterization of `collect_artifacts` would inherit an unvalidated hand-quoted interpolation). Migrate it with the traffic batch, not as the priority driver. |
| `adapter/windows_install.rs` (25) | staging dirs, paths, service names | `ps_quote` (:104, pub; rejects `\0\r\n`, doubles `'`; tests :1366/:1372/:1377) + `validate_windows_path` (:1077, tests :1655-1665) at most sites (sampled :225-228, :347, :522, :1067, :1241, :1266, :1346) | windows / PowerShell-over-SSH (`-EncodedCommand`) | operator/inventory-controlled | **QUOTED** — per-site; 62 `ps_quote` references in the file |
| `adapter/windows_membership.rs` (7) | node ids, bundle paths | `ps_quote` at every sampled site (:35, :125, :151-152, :180-181, :209, :224-226) | windows / PowerShell | inventory-controlled | **QUOTED** — per-site |
| `adapter/windows_traffic.rs` (23) | mesh IPs, temp paths | `ps_quote` + `validate_ip_arg` (:989, test :1726) (sites :49-51, :561-563, :659-661, :672-674, :700, :937-949) | windows / PowerShell | guest-observed | **QUOTED** — validated at value level, file-local validator |
| `adapter/ssh.rs` `base_ssh_command` `cmd.arg("-o").arg(format!("User={u}"))` (ssh.rs:423) | connection user | none (single `format!` argv element) | SSH client argv (no remote shell involved in this element) | operator/inventory-controlled (from `NodeConnection`) | **SAFE-BY-CONSTRUCTION (weak)** — the element is a lone `format!` of a config field; no remote re-parse of this element, but it is still an unvalidated interpolation at a privileged boundary |
| `adapter/windows.rs:329-345` `build_validator_script` | binary path + validator argv (subcommand, flags) | `ps_quote` on element 0 only — the remaining validator argv is emitted via `rest.join(" ")` (:342) unquoted into the PowerShell string | windows (PowerShell-over-SSH) | internally constructed (`WindowsDaemonProbe::build_argv` — fixed safe strings today) | **UNQUOTED-RISK** — same by-construction safety as the sudo joins above; must be included in the Step-4 signature flip or Windows ends half-migrated |

**SAFE-BY-CONSTRUCTION elsewhere (already seamed; cited as the model, not in scope):** `vm_lab/script_template.rs` — the canonical typed-`Binding` renderer (module contract :59-99: "the renderer owns the quoting; caller never does"; `Binding::RawFragment` :76-93 private-field + E0603 compile proof :84-85; sink-context table :31-38; backstop test `no_script_template_is_declared_outside_this_module` :109-110); `recover_guest_network.rs` :260-278 (three sudo-bash repair scripts — "the most privileged interpolation sites in the tree" — render via `script_template::render_*`; injection-rejection test :790); `vm_lab/mod.rs` all 32 production render sites (commit `0aff3c07`); `run_host_cmd` argv quoting (`mod.rs:5349`+, QH-13 CLOSED); the canonical validator `ensure_single_quoted_script_value(label, value, allow_empty)` (`mod.rs:3174`, `enum AllowEmpty` :3150-3153, QH-12 CLOSED); `run_remote_retrying` (`ssh.rs:495`) restricted to idempotent read-only probes.

Structural evidence that no seam exists today: `validate_ip_arg` is defined **three times** (`linux_traffic.rs:1036`, `macos_traffic.rs:659`, `windows_traffic.rs:989`); `shell_quote` exists in three variants (`vm_lab/mod.rs:35043`, `orchestrator/remote_shell.rs:351`, `orchestrator/stage/cross_network/substrate.rs:171`) plus `powershell_quote` (`mod.rs:35056`); **no file under `adapter/` references `script_template`** (grep: zero hits), and `mod script_template;` is private (`vm_lab/mod.rs:14`), so adapters cannot import it without a visibility change.

## 2) The class, precisely

**Sink semantics.** `run_remote(conn, script: &str, …)` places the script as a single argv element of the local `ssh` process (`ssh.rs:456` `cmd.arg(script)`). The OpenSSH exec channel transmits **one command string**; the remote sshd re-parses it with the login shell before exec (reasoning from OpenSSH exec-channel semantics; not separately verified in this repo). So the Rust-side argv shape is not a safety property: the effective sink is the remote shell. QH-19's six-row sink-context table records exactly this ("SSH post-host argv", `script_template.rs:37`). The PowerShell wrapper narrows but does not remove the surface: `-EncodedCommand` makes the *transport* inert, but the *interior* of the PS script is still a string where `$( )`, backticks, and quotes are live — the Windows seam needed is PS-script construction, not SSH quoting.

**Why per-site quoting is insufficient.** The 2026-07-25 review, verbatim (from `QualityHardeningTodo_2026-07-25.md:53-100`):

> "**Framing this as an *ordering* bug is insufficient.**"

> "So the fix had to make the renderer **own the quoting** (escape at interpolation via the `shell_quote` escaper that already existed at `mod.rs:37993`), not merely fix scan order. Order-independence is necessary but **not sufficient**." [line since moved — current: `mod.rs:35043`]

> "This item cites a validator that does not exist — `ensure_single_quoted_script_value` (see QH-12). It also calls the image check an 'allow-list'; it was a **deny**-list."

> "The `.replace("__` CI grep is the wrong control — evadable via `replacen`, `format!`, or a variable token… Use a type/module boundary so a bypass cannot compile."

> "'Fail closed on an unknown token in the template' would **break every launch** — `__PLACEHOLDERS__` appears in prose in `HOST_LAUNCH_SCRIPT` (`:5008`)…Only 'unconsumed **binding** ⇒ error' is safe." [line since moved — current: `script_template.rs:827`]

The adapter layer today is in the exact pre-fix position the review diagnosed: correct *at each site the author remembered* (hence QUOTED verdicts), with the safety property held by convention — the same "per-site discipline" that let the original QH-01 defect hide. The review also found the original fix's site list incomplete; this plan treats the adapter directory as the completion of that list, not a new class.

**What "structural" means here.** Three properties, all required:

1. **Typed construction.** A `RemoteCommand` newtype (and a PowerShell counterpart) whose `String` field is private and which has no `From<String>`/`Display` — the command string can only come into existence through the type's constructors. This is the `script_template.rs:101-110` boundary pattern (private field, no public constructor, compile-time proof) applied to the adapter sink.
2. **Allowlist validation at the seam.** Every interpolated value passes a per-class validator *before* any command string exists: node ids (alphabet `[A-Za-z0-9._-]+`, mirroring `Binding::Bare`, `script_template.rs:215-237`), IPs/CIDRs, POSIX/Windows paths, service names, utun names. Where a validator already exists per-file (`validate_ip_arg` ×3, `validate_utun_name`, `validate_windows_path`), hoist it; where not (e.g. `macos_traffic.rs:419` `remote_tmp`), add it. `ensure_single_quoted_script_value` remains the defense-in-depth layer for pre-quoted and RawFragment-adjacent values (its own doc, `mod.rs:3157-3173`, states escaping is load-bearing and this helper is the second control).
3. **Non-public raw seam.** `run_remote(conn, script: &str, …)` becomes `run_remote(conn, script: RemoteCommand, …)` (same for `_with_log`/`_retrying`/`_check` and `run_remote_ps`/`run_remote_ps_check`). After the migration, a raw `format!` result **cannot compile** against the sink — the review's "a bypass cannot compile" requirement, met by the type system rather than a grep.

**Seam precedent: QH-13.** QH-13 (CLOSED 2026-08-29, commits `496bf2fb`, `cd573224`) established the seam pattern for the argv-shaped sink: `remote_command_string` at the `run_host_cmd` chokepoint, mutation-verified tests bound to the seam, and an explicit scope note that the whole-script family (this plan's subject) was left open. This plan is that item's designated successor for `adapter/`; it reuses the pattern (seam fn + tests bound to the real lowering, not local re-implementations) and cites the closure.

## 3) Options, ranked

Decision lens (from this repo's priorities): serves core goals (live-lab evidence must be trustworthy; the class must be *unable to recur*) → most secure → best long-term.

**Option A — typed argv-only builder end-to-end (strictest, not recommended as the first move).** Every remote invocation becomes a structured argv-like `RemoteCommand` lowered per-dialect by the transport. The hard limit: the SSH exec channel carries one string (no argv), so true argv-only transport requires either a remote-side decoder (which relocates the shell sink into a decoder invocation) or a structured protocol the sshd does not speak. PowerShell-over-SSH gets closest — `-EncodedCommand` is already a byte-exact, shell-inert transport (`windows_install.rs:83-96`). Adopting A everywhere means changing every remote contract (host scripts, membership bundles, traffic probes) at once. Highest assurance, highest blast radius, and it ultimately still needs an allowlist validator for what goes *inside* each command. Verdict: correct destination, wrong first step; Option B is A's foundation and can be extended toward A later.

**Option B — single quoting seam + allowlist validation + non-public raw sink (RECOMMENDED).** As specified in §2: extend the proven `script_template` boundary to the adapter layer, wrap the four `run_remote*` and two `run_remote_ps*` sinks in newtypes, hoist the triplicated validators into one seam module, migrate sites leaf-first, then make the raw `&str` sink unreachable. This is the same structural shape the codebase already trusts twice — the renderer's private-field boundary and `rustynetd`'s privileged helper (exact-match argv allowlist `validate_request`; adversarial self-audit corpus `allowlist_audit_corpus()` at `privileged_helper_allowlist_audit.rs:120`; fail-on-regression CI via `rustynetd privileged-helper-allowlist-audit`, `rustynetd/src/main.rs:326`, regression tests :5486-5500, corpus accept/reject tests :412-459). Best long-term: the type boundary makes the next adapter author *unable* to reintroduce the class silently.

**Option C — per-site fixes only (REJECT).** The review's judgment is direct: per-site discipline and scan-based controls are what failed the first time ("necessary but **not sufficient**"; the grep "is the wrong control"). The adapter layer already *has* per-site quoting everywhere it was remembered — and still ships an UNQUOTED-RISK argv-join family and an unvalidated `rm -f '{remote_tmp}'`. Rejected.

## 4) Implementation sketch (Option B)

**Step 1 — visibility (S).** `vm_lab/mod.rs:14` `mod script_template;` → `pub(crate) mod script_template;`. Expose `shell_quote` (`mod.rs:35043`) and `powershell_quote` (`mod.rs:35056`) to `crate::vm_lab::orchestrator::adapter` (currently private `fn`s; `script_template` reaches them via `super::`). Keep the renderer's internal boundary intact — the backstop test (`script_template.rs:109-110`) must keep passing.

**Step 2 — newtypes at the sink (S).** In `adapter/ssh.rs`: `pub(crate) struct RemoteCommand(String)` — private field, no `From<String>`, no `Display`/`Debug` of the interior (secrets hygiene §10.6 applies to any future Debug impl). Constructors:
- `RemoteCommand::from_template(rendered: ScriptTemplateOutput)` — accepts only renderer output;
- `RemoteCommand::from_validated_single(label: &str, value: &str) -> Result<Self, …>` — runs `ensure_single_quoted_script_value` then `shell_quote`;
- `RemoteCommand::from_args(label, args: &[ValidatedArg]) -> Result<Self, …>` — space-joins *validated* args (replaces the `argv.join(" ")` sites at `linux.rs:209` / `macos.rs:217` / `windows.rs` argv variant);
- `ValidatedArg::ip`, `::node_id`, `::path`, `::service`, `::cidr`, `::utun` — each a thin constructor over the hoisted per-class validator.
Mirror with `PowerShellScript(String)` in the Windows family over `run_remote_ps` (`windows_install.rs:122`), using `ps_quote` + a PS-metacharacter allowlist for the script *interior* (`$( )`, backtick, quotes rejected in interpolated values), keeping `encode_ps_command`/`build_ps_invocation` as the transport wrapper. `run_remote_argv` (`stage/negative_control.rs:485`) is production code in the negative-control stage (called at :608/:623/:691/:721, before that file's first `#[cfg(test)]` at :811) and is out of scope because it is **argv-only** (`RemoteShellHost::run_argv`), not because it is a test. The Step-5 gate must not treat `run_remote_argv` as a test exemption; it is simply not a string sink.

The `ValidatedArg` class list is completed with: `::connection_user` (applied where `NodeConnection` feeds `base_ssh_command`; see §8 question 4 / §1 table), `::interface_name` (reuse `is_safe_interface_name` from `recover_guest_network.rs` — test-pinned at :790 against `"a;rm -rf"` and spaces — rather than a new validator), `::bundle_filename`, `::service_name` (pin the existing `windows_install.rs` constants), and `::port`. Two binding rules for the newtypes: (1) every PS-side constructor is fallible (`Result`) because `ps_quote`/`powershell_quote` refuse rather than sanitize; (2) `ValidatedArg::path` pairs shape validation with confinement (per `script_template.rs:38`, quoting cannot contain a path). Design goal: the newtypes must let a later Option-A transport migration (per-sink `-EncodedCommand`) happen inside the seam without call-site changes.

**Step 3 — hoist validators (S/M).** One seam module (e.g. `adapter/validated_args.rs`) owning: the single `validate_ip_arg` (deduplicating `linux_traffic.rs:1036` / `macos_traffic.rs:659` / `windows_traffic.rs:989`, preserving each file's existing tests by re-export), `validate_utun_name` (`macos_install.rs:692`), `validate_windows_path` (`windows_install.rs:1077`), and new node-id/service/CIDR/path validators. Rule: validators reject before any string is built — the FIRST fail-closed test is exactly **"a value containing a shell metacharacter is rejected before any command string exists"**, asserted via the constructor's `Err` return (the type must not let the rejected value reach a `String`).

**Step 4 — migration, leaf-first (M).** (a) The three argv-join sites (`linux.rs:209`, `macos.rs:217`, `windows.rs` variant) — smallest set, highest verdict risk. (b) Traffic adapters (`linux_traffic.rs` 32, `windows_traffic.rs` 23, `macos_traffic.rs` 21) — including fixing `macos_traffic.rs:419` (`rm -f '{remote_tmp}'` gets a path validator). (c) Install/membership adapters. (d) Flip `run_remote*`/`run_remote_ps*` signatures to the newtypes — any missed site now fails compilation.

**Step 5 — pin the boundary (S).** Source-scan unit test (Rust, not shell grep — the review called the grep "the wrong control"): assert no `run_remote(`-family call site passes a `format!`/`replacen` result directly (post-signature-flip this is compiler-enforced; the test pins the *absence* of a raw-`&str` sink reappearing) and that `RemoteCommand`'s field stays private outside `adapter/ssh.rs`. Style follows the existing injection-pinning tests: `shell_metacharacters_cannot_reach_the_script` (`vm_lab/mod.rs:51334`), `orchestrator_arg_safety_is_the_injection_boundary` (:51861), `remote_command_string_is_inert_for_every_shell_metacharacter` (:52507), `build_windows_bundle_atomic_install_script_rejects_metacharacters` (:48095).

## 5) CI gate

Add a sibling gate to the secrets-hygiene family: `crates/rustynet-cli/src/bin/adapter_injection_gates.rs` (a Rust binary per the shell-to-Rust rule, AGENTS.md §4) plus a two-line wrapper `scripts/ci/adapter_injection_gates.sh` mirroring `scripts/ci/secrets_hygiene_gates.sh` (a 2-line `exec cargo run --quiet -p rustynet-cli --bin …` wrapper, :2). Gate checks, failing loudly on: (1) any `run_remote*`/`run_remote_ps*` call site in `adapter/` whose script argument is syntactically a `format!`/`replacen`/concatenation expression rather than a newtype constructor call; (2) any *new* file under `adapter/` defining a local copy of a seam validator (`validate_ip_arg`, `shell_quote`, `ps_quote`) — triplication was the smell that hid the original defect; (3) any `pub fn run_remote(conn, script: &str` signature reappearing (raw-sink resurrection). False-positive handling: an explicit, reviewed allowlist inside the gate binary (each entry with a reason comment), never inline `#[allow]`-style suppression — mirroring how `privileged_helper_allowlist_audit.rs` treats its reviewed corpus. The gate follows the privileged-helper audit's fail-on-regression contract: a new violation is a CI failure, not a warning. Run it in the same CI phase as `secrets_hygiene_gates.sh`.

Gate precision requirements: (1) the scan rule excludes `#[cfg(test)]` regions (QH-01 precedent: 18/50 grep hits were in-test re-implementations); test-only fixtures live under `#[cfg(test)]` and are audited, not blanket-allowed; (2) the gate states its precedence against the QH-12 guard (`ensure_single_quoted_script_value`, `mod.rs:3174`) and the QH-13 chokepoint (`remote_command_string`) — satisfying this gate must never justify removing either; (3) the allowlist of deliberate exemptions is adversarially audited in the style of `privileged_helper_allowlist_audit.rs` (corpus + mislabel-regression test, :120/:412-459).

## 6) What NOT to do

- **No blanket escape-everything helper** that launders unvalidated values through a generic escaper — the review: "four competing idioms for this rule are what let the QH-01 defect hide." Escaping is load-bearing; validation is the seam; conflating them recreates the defect.
- **No per-request or debug bypass** — no `RemoteCommand::raw()`, no `unsafe`-adjacent escape hatch, no `#[cfg(debug_assertions)]` raw path. One hardened execution path (AGENTS.md §3).
- **No weakening of the privileged-helper allowlist** (`rustynetd/src/privileged_helper.rs`) to ease adapter migration; the helper stays exact-match argv.
- **No grep/regex-only CI control as the primary defense** — the review: evadable via `replacen`, `format!`, or a variable token. Scanning is a backstop; the non-public sink is the control.
- **No "fail closed on unknown token in the template"** re-interpretation — the review: that "would **break every launch**"; only "unconsumed **binding** ⇒ error" is safe.
- **No dry-run-as-pass in live proof** — per the FAIL-LOUD live-stage spec (CrossPlatformRoleParityRoadmap §2), live result = stage status from the stage's own report artifact; the run-matrix row alone is not proof (AGENTS.md §12.3).

## 7) Sizing and live proof

| Step | Size | Closest live-lab proof (adapter paths exercised) |
| --- | --- | --- |
| 1-2: visibility + newtypes + first fail-closed test | S | compile + unit gates (no lab needed) |
| 3: hoist validators | S/M | unit gates; `traffic_test_matrix` (exercises all three traffic adapters' probe paths) |
| 4a: leaf argv-join sites | S | `linux_stage_*` role stages; `traffic_test_matrix` |
| 4b: traffic adapters (+ `:419` fix) | M | `traffic_test_matrix`, `live_two_hop_validation` (the chained-exit path exercises traffic sinks end-to-end) |
| 4c: install/membership adapters | M | `linux_stage_*`; `macos_stage_*` family (macOS install/membership); `windows_stage_bootstrap` gates all downstream Windows stages (currently 5 fail / 0 pass per the live ledger — Windows proof of this step is blocked until that stage goes green; record the dependency in the parity ledger, do not substitute dry-run evidence) |
| 5: raw sink private + scan test | S | full `--node` orchestrator run; verify the appended row in `documents/operations/live_lab_node_run_matrix.csv` (quote-aware parse; take pass/fail from the stage's report artifact, not the column) |
| CI gate (§5) | S | CI itself; no lab dependency |

Sequencing note: this plan deliberately does not touch any live-lab schedule. It slots into the existing Linux→macOS→Windows iteration (LiveLabExecutionEfficiencyPlan) as the adapters migrate; per-step live proof reuses whatever role stage already exercises the migrated file, with `rebuild_nodes` limited to the patched node per the efficiency plan.

## 8) Open questions for adversarial review

1. **Sink coverage completeness.** Are there remote-string sinks outside `adapter/` that accept runtime values — e.g. `remote_shell.rs` (`shell_quote` at :351, entry fns `run_remote_shell_command*` at `mod.rs:33833`/:33932/:34249) and the cross-network substrate (`substrate.rs:171`)? This plan scoped `adapter/` because it is the unseamed majority, but a completion claim ("the class is eliminated") requires enumerating *every* `String`-typed remote sink. Should the scan test (Step 5) be widened to repo-wide sink discovery, and how are deliberate exceptions (test helpers like `run_remote_argv`, `negative_control.rs:485`) excluded without becoming a bypass channel?
2. **`run_remote_retrying` contract.** Its doc restricts it to idempotent read-only probes (`ssh.rs:495`), but nothing enforces that structurally. Should the newtype family include a `ReadOnlyProbe` marker type so the restriction is compiler-checked, or is doc-plus-review acceptable here?
3. **PowerShell allowlist exactness.** `ps_quote` handles quoting, but the interior-allowlist (rejecting `$( )`, backtick, `;`, `|` in *values*, as opposed to the script text) needs a precise metacharacter set for PowerShell's parser — what is the authoritative list, and does it differ across `powershell.exe` (Windows PowerShell 5.1) vs `pwsh` if the lab ever uses both?
4. **`base_ssh_command` `User={u}`.** The user comes from the inventory (`NodeConnection`) and is interpolated unquoted into an SSH option (`ssh.rs:423`). OpenSSH parses option values without a shell, but a hostile inventory could still inject option syntax (e.g. a value containing whitespace/Y-flag shapes). The concrete mechanism is newline-based: OpenSSH option values are config-line syntax, so a `\n` inside the user value starts a new `ssh_config` option line (e.g. `ProxyCommand`). Add a `ValidatedArg::connection_user` class with a strict alphabet (no control characters, no whitespace beyond the inventory's documented shape) applied where `NodeConnection` feeds `base_ssh_command`. What alphabet is legitimate for the lab's user names?
5. **Migration-vs-blocked-Windows proof.** Step 4c's Windows evidence depends on `windows_stage_bootstrap` (5 fail / 0 pass). If the bootstrap stage remains red when the adapters migrate, is unit-level + `traffic_test_matrix`-style local Windows coverage an acceptable intermediate record (clearly marked non-live), or does the parity mandate require holding the Windows migration until the stage is green? **Answered (policy):** until `windows_stage_bootstrap` is green, Windows migration evidence may be recorded as unit-level + local Windows coverage **only if** (a) every such artifact is explicitly marked non-live, and (b) the dependency is recorded in the parity ledger (`CrossPlatformRoleParityRefresh_2026-07-23.md`). The parity mandate (per-role × per-OS live proof) remains unmet for the Windows migration until the stage passes live; a green unit suite never substitutes for the live cell.
6. **Newtype vs enum for dialects.** One `RemoteCommand` type with a dialect tag, or separate `PosixCommand`/`PowerShellScript` types? Separate types prevent cross-dialect mistakes (a PS-quoted value handed to a POSIX sink) at the cost of more surface; which does the codebase's fail-closed instinct favor, and do any call sites legitimately need both dialects for one logical operation?
7. **Template-vs-validated split.** Should long-lived adapter scripts (install/membership) move onto full `script_template` templates (bindings + renderer, maximum rigor) rather than validated-arg composition, reserving `from_args` for genuinely one-line probes? Where is the cost/benefit line, and does the answer differ per adapter family?

## 9) Review disposition

Folded from `Qh01TemplateInjectionEliminationPlanAdversarialReview_2026-09-02.md` §9:

- A1: folded — `run_remote_argv` reclassified as production (argv-only) negative-control code, not a test exemption; Step-5 gate barred from treating it as one.
- A2: folded — `User={u}` anchor corrected to `ssh.rs:423`; newline-based ssh option-line injection mechanism and `ValidatedArg::connection_user` class added to §8 Q4.
- A3: folded — `macos_traffic.rs:419` reclassified: weakest *guarded* site, `remote_tmp` is a compile-time const (`:398`), no live injection; migrate with the traffic batch.
- A4: folded — validator class list completed (`connection_user`, `interface_name` via `is_safe_interface_name`, `bundle_filename`, `service_name`, `port`) plus the two binding newtype rules and the Option-A-forward design goal.
- A5: folded — `windows.rs:329-345` `build_validator_script` (`rest.join(" ")` at :342) added to the UNQUOTED-RISK family as its own §1 table row.
- A6: folded — QH-13 closure (`496bf2fb`, `cd573224`) cited in §2 as the seam precedent this plan succeeds.
- A7: folded — CI-gate precision added: `#[cfg(test)]` exclusion, stated precedence against QH-12/QH-13, adversarially audited allowlist.
- A8: folded — §8 Q5 answered with the explicit non-live-evidence policy and parity-ledger dependency record.
- Step 4a landed — the three validator argv-join sink sites (linux.rs, macos.rs, windows.rs build_validator_script) now build their commands through the validated seam (`ValidatedArg::cli_token` + `RemoteCommand::from_args` / `PowerShellScript::from_call_argv`).
- Step 4b landed — the argv-shaped traffic-adapter sites (linux_traffic: exit route-advertise, diag rm, issue mkdir + sudo-env issue; macos_traffic: mesh ping with stderr merged, diag rm, issue mkdir + env-sudo issue; windows_traffic: Get-Content pubkey, live-identity `& path status`, diag Remove-Item, both Stop-Service sites) now render through the validated seam via `RemoteCommand::from_args` / `from_args_with_stderr_merged` / `PowerShellScript::from_call_argv`; each migrated site has a rendering test and each adapter a rejection test. The seam's `cli_token` alphabet gained `/` so `KEY=/absolute/path` env-assignment tokens stay one safe token.
- Step 4c landed — the argv-shaped install/membership adapter sites (linux_install: `run_systemctl`; linux_membership: init-membership + e2e-membership-add; macos_install: workdir probe + assignment-pubkey read; macos_membership: init-membership + peer-add + both staging `mkdir -p` sites; windows_install: assignment-pubkey `Get-Content -Raw`) now render through the validated seam the same way; each migrated site has a rendering test and each migrated adapter a rejection test. The seam gained a `capability_csv` class (charset `[A-Za-z0-9._,-]+`, hoisted from linux/macos_membership's identical local `shell_safe_arg` guards, now removed); `hex_32_safe_arg` stays as the stricter per-site 64-hex guard layered under `cli_token`. Constant-literal sink scripts (no `format!`/concatenation) remain out of inventory by the Step 4b precedent. The raw sink-call-site pin is unchanged at 158 (migrations keep the existing sink call, so the structural count only moves at Step 4d's sink-signature flip).

## 10) Step 4b/4c remainder (input to Step 4d)

Sites whose script argument is built by `format!`/concatenation but are SHELL-shaped (pipes, `&&`/`||`, `;`, non-trailing redirections, `if`/`for`/`try` blocks, multi-statement PowerShell, command substitution). These cannot migrate to the argv seam without changing remote behavior; Step 4d's typed renderer-output constructor is the planned shape.

| Site | Interpolated values (classes) | Shell operators present | Migration shape 4d needs |
| --- | --- | --- | --- |
| linux_traffic.rs gossip_export_remote_command (~:324) | unit/marker/user/secret/passphrase (compile-time consts) | `;`, `\|\|`, `{}` group | Multi-statement renderer emitting `RemoteCommand` |
| linux_traffic.rs ping_mesh_peer (~:419) | mesh ip (validated via `validate_ip_arg`) | `;`, `$?`, `printf` marker protocol | Multi-statement renderer |
| linux_traffic.rs probe_denied_peer (~:462) | ip (validated) | `>/dev/null 2>&1` (non-trailing), `\|\|` | Redirect-position-aware renderer |
| linux_traffic.rs collect_artifacts tar_script (~:737) | remote_tmp (const-derived path) | `;`, `$(id -u)` substitution, `\|\|` fallback | Multi-statement renderer |
| linux_traffic.rs issue chmod `&&`/glob (~:999) | dir (const-derived) | `&&`, glob `*` | Two-command or glob renderer |
| linux_traffic.rs issue `ls -1 2>/dev/null` (~:1008) | dir (const-derived) | trailing `2>/dev/null` (fd-specific) | Fd-redirect trailer constructor |
| linux_traffic.rs cleanup `rm -f && rm -rf` (~:1024) | env, dir (const-derived) | `&&` | Two-command renderer |
| macos_traffic.rs collect_wireguard_public_key (~:250) | pub_key_path (const-derived) | `if/then/else/fi`, `>/dev/null`, `\|\|` | Branching renderer |
| macos_traffic.rs probe_denied_peer (~:370) | ip (validated) | `>/dev/null 2>&1`, `&&`, `\|\|` | Redirect + branch renderer |
| macos_traffic.rs collect_artifacts diag tar (~:400) | remote_tmp, MACOS_STATE_ROOT | `\|\|` fallback, multiple excludes | Multi-command renderer |
| macos_traffic.rs cleanup sudo rm batch (~:466) | MACOS_STATE_ROOT paths | `2>/dev/null \|\| true` | Fd-redirect + ignore-failure trailer |
| macos_traffic.rs collect_daemon_failure_reason (~:509) | log path (const-derived) | `2>/dev/null \|\| true` | Fd-redirect trailer |
| windows_traffic.rs collect_node_id_script (~:84) | env_path (const-derived) | multi-statement, `throw`, regex | PS multi-statement renderer |
| windows_traffic.rs ping_mesh_peer (~:146) | ip (ps-quoted, validated) | `try/catch`, `if/else`, `exit` | PS control-flow renderer |
| windows_traffic.rs probe_denied_peer (~:176) | ip (ps-quoted, validated) | `if/else`, `exit` | PS control-flow renderer |
| windows_traffic.rs build_diag_archive_script (~:460) | staging/logs/zip paths | multi-statement, `if/else`, `Join-Path` | PS multi-statement renderer |
| windows_traffic.rs windows_dataplane_reset_script (~:599) | rule names (consts), `$($_.Name)` remote data | multi-statement, pipelines | PS multi-statement renderer (remote data must stay non-interpolated) |
| windows_traffic.rs build_runtime_state_cleanup_script (~:630) | state root, staging | multi-statement, `foreach` | PS multi-statement renderer |
| windows_traffic.rs collect_daemon_failure_reason (~:697) | log path | `if (Test-Path)` | PS control-flow renderer |
| windows_traffic.rs windows_node_clean_assert_script (~:725) | service names (consts) | multi-statement, pipelines | PS multi-statement renderer |
| windows_traffic.rs issue ensure_script (~:934) | staging dir, issue dir | two statements joined by `;` | PS multi-statement renderer |
| windows_traffic.rs issue run_script (~:942) | rustynet path, subcmd, env, dir | `$env:` assignment, `;`, `if throw` | PS multi-statement renderer |
| windows_traffic.rs issue list_script (~:954) | issue dir | pipeline `\|` | PS pipeline renderer |
| windows_traffic.rs issue cleanup_script (~:975) | env, dir | two statements joined by `;` | PS multi-statement renderer |
| linux_install.rs bootstrap verify_script (~:127) | binary/key/env paths (compile-time consts) | `&&`, `$(stat -f …)` substitution | Multi-statement renderer |
| linux_install.rs install build/enforce branch (~:213, ~:276-295) | workdir (path), archive/report path consts | `&&`, `cd`, `tar`, `echo >>` env append | Multi-statement renderer |
| linux_install.rs relay install_cmd (~:338) | src_dir (operator workdir / `$HOME`-derived), const binary | `sh -c` subshell, `env` indirection, `&&`, `cd` | Env-assignment + subshell renderer |
| linux_install.rs uninstall (~:386) | state/run dirs (consts) | `;`, `\|\|`, `&&` chain | Multi-command renderer |
| linux_membership.rs snapshot readback (~:111) | snapshot path (const) | `&&`, `cat \| base64` pipe | Two-command + pipe renderer |
| linux_membership.rs distribute_signed_bundle (~:168) | tmp/dst/log paths, mode/owner consts | `&&` chain, `printf \| tee` pipe, `(…)` group | Multi-command + pipe renderer |
| linux_membership.rs distribute_verifier_key (~:197) | dst/tmp paths, sha256 (validated) | `&&` chain, `$(sha256sum \| awk)` substitution | Multi-command + substitution renderer |
| macos_install.rs verify_script (~:152) | binary/key/env paths (consts) | `&&`, `$(stat -f …)` substitution | Multi-statement renderer |
| macos_install.rs build_cmd workdir branch (~:295) | workdir (path), archive consts | `&&`, `cd`, `tar`, `echo >>` | Multi-statement renderer |
| macos_install.rs start_daemon (~:416) | plist path (const) | `\|\|` fallback across launchctl verbs | Multi-command renderer |
| macos_install.rs enforce install script (~:645) | node id/network id/utun/cidrs (validated), STUN gateway detection | `;`, `if/then`, `$(route \| awk)` substitution | Multi-statement renderer (env flags via argv once 4d) |
| macos_install.rs uninstall (~:660) | binary/plist/state paths (consts) | `&&` chain | Multi-command renderer |
| macos_install.rs relay verifier install (~:790) | state-root path (const) | `sh -c` subshell, `&&` chain | Subshell renderer |
| macos_install.rs relay install_cmd (~:825) | src_dir (workdir/`$HOME`-derived) | `env` indirection, `sh -c`, `&&`, `cd` | Env-assignment + subshell renderer |
| macos_install.rs relay dep check (~:923) | guest registry path (derived) | `;`-joined `test … \|\| echo` batch | Multi-command renderer |
| macos_membership.rs owner_key_read_script (~:47) | pubkey path (const) | `if/then/else/fi`, `;`, `$(cat 2>&1 \| head)` | Branching renderer (marker protocol) |
| macos_membership.rs snapshot readback (~:282) | snapshot path (const) | `if`, `cat \| base64` pipe, stderr diagnostic | Branching + pipe renderer |
| macos_membership.rs distribute_signed_bundle (~:168 install) | tmp/dst/log paths, mode/owner consts | `&&` chain, `\|\|`, `printf \| tee` pipe | Multi-command + pipe renderer |
| macos_membership.rs distribute_verifier_key (~:228 install) | tmp/dst paths, sha256 (validated) | `&&` chain, `$(shasum \| awk)` substitution | Multi-command + substitution renderer |
| windows_install.rs ensure staging dir (~:297) | staging dir (const) | `\| Out-Null` pipeline | Single-cmdlet renderer (drop the pipe) |
| windows_install.rs vendor extract (~:344) | workdir, vendor archive (paths) | multi-statement, `$vars`, backtick strings, `Join-Path` | PS multi-statement renderer |
| windows_install.rs build release script (~:377) | workdir/bootstrap/config/report paths | `Set-StrictMode` prefix, `Set-Location`, `&` invocation | PS multi-statement renderer |
| windows_install.rs service install script (~:388) | install root, service/node/role ids (validated) | `Set-StrictMode` prefix, `&` invocation | PS multi-statement renderer |
| windows_install.rs verify rustynetd.exe (~:419) | binary path (const) | `if (-not (Test-Path)) { throw }` | PS control-flow renderer |
| windows_install.rs enforce patch script (~:519) | env path (const-derived) | multi-statement, pipeline, `if` blocks | PS multi-statement renderer |
| windows_install.rs tunnel-ip readiness (~:542) | adapter name (validated) | multi-statement fragment composition | PS multi-statement renderer |
| windows_install.rs start daemon probe (~:563) | service name (const) | loops, `$LASTEXITCODE` branches, `throw` | PS control-flow renderer |
| windows_install.rs uninstall ensure dir (~:594) | staging dir (const) | `\| Out-Null` pipeline | Single-cmdlet renderer |
| windows_install.rs uninstall script (~:617) | uninstaller/service/install/state paths | `Set-StrictMode` prefix, `&` invocation | PS multi-statement renderer |
| windows_install.rs trust dir (~:935) | trust dir (const) | `\| Out-Null` pipeline | Single-cmdlet renderer |
| windows_install.rs e2e bootstrap script (~:1082) | many DPAPI/key paths, RNG material | multi-statement, `try/finally`, scriptblock invocation | PS multi-statement renderer |
| windows_install.rs run_service_action (~:1140) | service name (const) | `Set-StrictMode` prefix before cmdlet | PS prefix-aware renderer |
| windows_install.rs relay mkroot+harden (~:1324) | relay root (const) | `\| Out-Null` + ACL harden statements | PS multi-statement renderer |
| windows_install.rs relay install verifier (~:1347) | tmp/dst paths (const-derived) | `Set-StrictMode` prefix, `Move-Item`, harden call | PS multi-statement renderer |
| windows_install.rs relay replay store (~:1362) | store path (const) | `if (-not (Test-Path))`, pipe | PS control-flow renderer |
| windows_install.rs relay install env (~:1390) | tmp/env paths (const-derived) | `Set-StrictMode` prefix, `Move-Item`, harden call | PS multi-statement renderer |
| windows_install.rs relay create service (~:1397) | service/binary/env paths (consts) | `if/else`, `sc.exe create/config`, `throw` | PS control-flow renderer |
| windows_install.rs relay start probe (~:1406) | service name (const) | loops, `$LASTEXITCODE` branches, `throw` | PS control-flow renderer |
| windows_membership.rs owner key read (~:37) | pubkey path (const) | `$var`, `if/throw`, multi-statement | PS control-flow renderer |
| windows_membership.rs add-peer w/ helper (~:117) | node/owner ids, hex, capabilities (validated) | `if` + function definition, scriptblock | PS function-provision renderer |
| windows_membership.rs snapshot readback (~:127) | snapshot path (const) | preference prefix statements + `[Convert]::ToBase64String` | PS prefix-aware renderer |
| windows_membership.rs ensure dirs (~:154) | staging/dst parent (consts) | `foreach`, `if`, `\| Out-Null` | PS loop renderer |
| windows_membership.rs install script (~:183) | tmp/dst/log paths | `Set-StrictMode` prefix, conditional `Set-Content` | PS multi-statement renderer |
| windows_membership.rs verifier ensure dir (~:211) | dst parent (const) | `if`, `\| Out-Null` | PS control-flow renderer |
| windows_membership.rs verifier install (~:228) | tmp/dst paths, sha256 (validated) | `Set-StrictMode` prefix, `Get-FileHash`, `if/throw` | PS multi-statement renderer |
