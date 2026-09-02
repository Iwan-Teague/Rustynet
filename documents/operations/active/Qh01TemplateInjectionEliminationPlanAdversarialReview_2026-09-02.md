# Adversarial Review — QH-01 Phase-2 Template-Injection Elimination Plan

**Reviewed:** `Qh01TemplateInjectionEliminationPlan_2026-09-02.md` (115 lines)
**Date:** 2026-09-02
**Method:** docs-only adversarial review. Every file:line anchor the plan cites was re-opened at commit `fc6ed568` in a clean tree; every §1 count was re-derived with an independent sink-pattern grep; §7 stage claims were re-counted from the live `--node` ledger (`documents/operations/live_lab_node_run_matrix.csv`) with a quote-aware CSV reader. No claim in this review is taken from the plan or its predecessor docs without independent verification; where this review quotes the plan or the QH-01 review block, the quote is verbatim.
**No live lab was exercised.** See §10.

---

## §0 Verdict

| Plan section | Claim under attack | Verdict |
|---|---|---|
| §1 inventory | 13 adapter files, ≈164 sites, per-file table | **HOLDS** — counts reproduce exactly (§1 below) |
| §1 classification | argv-join family UNQUOTED-RISK; `macos_traffic.rs:419` "weakest audited site" | **HOLDS WITH AMENDMENT A3** — the weakness is real but its classification is off |
| §2 sink semantics + class statement | sshd re-parse, `-EncodedCommand` inert transport / live interior, three structural properties | **HOLDS** — strengthened by the closed QH-13 precedent |
| §3 option ranking | B (seam + newtypes + validators) recommended; A not first; C rejected | **HOLDS** |
| §4 migration steps + validator set | leaf-first, hoist validators, newtype set | **HOLDS WITH AMENDMENTS A4/A5** — validator class list is incomplete |
| §5 CI gate | new gate binary + wrapper | **HOLDS WITH AMENDMENT A7** — precision requirement missing |
| §6 anti-patterns | six prohibitions | **HOLDS** |
| §7 sizing + live proof | stage mapping, Windows blocked | **HOLDS** — `windows_stage_bootstrap` 5 fail / 0 pass verified against the live ledger |
| §8 open questions | seven questions | **HOLDS; Q4/Q5 answered here** (A2, A8) |
| Anchors (whole doc) | file:line citations | **HOLDS WITH AMENDMENTS A1/A2** — one misclassification, one stale line number; the block-quoted historical anchors are attributed quotes, not plan claims |

**Overall verdict: READY-WITH-AMENDMENTS.** The plan's core claims — inventory completeness, the structural class statement, the Option-B ranking, and the sizing/proof mapping — all survive attack. Eight amendments are required before execution (§9); none changes the plan's direction, and two (A6, A8) mostly add citations and decisions the plan already gestures at in §8.

---

## §1 Attack: inventory completeness

**Method.** Independent count with `rg -c 'run_remote_ps\(|run_remote_ps_check\(|run_remote_with_log\(|run_remote_retrying\(|run_remote_check\(|run_remote\('` over every file in `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/`.

**Result: the plan's table reproduces exactly.** linux.rs 2, linux_install.rs 13, linux_membership.rs 6, linux_traffic.rs 32, macos.rs 2, macos_install.rs 15, macos_membership.rs 8, macos_traffic.rs 21, windows.rs 2, windows_install.rs 25, windows_membership.rs 7, windows_traffic.rs 23, ssh.rs 8 — 162 call lines total. Adding the two definitions in `windows_install.rs` (`run_remote_ps` :122, `run_remote_ps_check` :132) plus the four `ssh.rs` definitions (run_remote :432, run_remote_with_log :442, run_remote_inner :456, run_remote_retrying :495, run_remote_check :524 — five fns, one of which is the shared inner) reconciles the plan's "≈164" without residue.

**Missed files? None.** The adapter directory contains six files the plan's table does not list: `android.rs`, `ios.rs`, `factory.rs`, `verifier_key.rs`, `node_adapter.rs`, `mod.rs`. Grep confirms **zero** `run_remote*` call sites in all six, and zero `Command::new`/`.arg(`/`adb`/`idb` exec sinks (the only hits are a test-name string in `factory.rs:169` and an unrelated `expect_err` in `verifier_key.rs:108`). The inventory is complete for the sink family it declares.

**Definition sites.** The plan's sink definitions are all where it says: `ssh.rs:432/:442/:456/:495/:524` and `windows_install.rs:122/:132` — verified by direct read. `cmd.arg(script)` sits at `ssh.rs:465` inside `run_remote_inner` (the plan cites :456, the `fn` line — acceptable).

**One omission in the *family*, not the count — Amendment A5.** The plan's UNQUOTED-RISK argv-join family names `linux.rs:209` and `macos.rs:217` (`format!("sudo -n {}", argv.join(" "))` — both verified verbatim). It does not name the Windows analogue: `windows.rs:329-345` `build_validator_script` ps_quote's the binary path but emits the remaining validator argv with `rest.join(" ")` unquoted into the PowerShell string (:342). Today those elements are the plan-correct "fixed safe strings" (subcommand + flags from `WindowsDaemonProbe::build_argv`), so it belongs in the same UNQUOTED-RISK-by-construction bucket as the sudo joins — but a seam inventory that misses it will "flip the signature" on two of three platforms and leave the third half-migrated. See A5.

---

## §2 Attack: the class statement

The plan claims the class is structural: **one seam** (the `run_remote*` lowering into `ssh.rs`) **+ typed newtypes with private raw constructors + hoisted validators + a non-public raw sink**. Attacked from four angles:

**1. Is the seam actually single?** The lowering is real and chokepointed: every POSIX-path remote string ultimately crosses `ssh.rs` `run_remote*`, which does `cmd.arg(script)` (:465) — and the QH-13 closure established the adjacent argv-shaped chokepoint (`remote_command_string`, `run_host_cmd`) with mutation-verified tests. The PS path adds one more seam (`build_ps_invocation` → `encode_ps_command` → the same `run_remote`), which the plan correctly treats as "inert transport, live interior." Attack fails: the seams are enumerable and few, and the plan's §8 question 1 correctly flags that a *completion claim* needs a repo-wide sink census — which is the right humility, not a defect.

**2. `ValidatedArg::path` accepting too much.** Real risk. `script_template.rs:31-38` sink table (verified verbatim, including the QH-13 row) is explicit that **path composition is confinement, orthogonal to quoting**: `shell_quote("../../etc/passwd")` is a safe word that still traverses. If `ValidatedArg::path` validates only shape, the newtype launders traversal. Amendment A4 requires the path class to pair shape with confinement, per the plan's own cited table.

**3. `sudo -n` prefixing.** `linux.rs:209`/`macos.rs:217` prepend `sudo -n ` to a joined argv. Under Option B these become `RemoteCommand::sudo(validated argv)` — the prefix is builder-owned, not caller-formatted, so the attack fails *provided* the newtype's `from_args` path is the only constructor. The plan's private-field requirement is what makes this hold; it is correctly specified.

**4. The PowerShell quoting model.** Verified at both layers: `ps_quote` (`windows_install.rs:104-116`) rejects NUL/CR/LF and applies single-quote doubling (`'` → `''`, test-pinned at :1366/:1372/:1377); `powershell_quote` (`mod.rs:35056`) is the same model plus a control-character refusal, and returns `Result`. `-EncodedCommand` (UTF-16LE + base64, `encode_ps_command` :81-92) makes the *transport* inert — the plan's characterization is correct: sshd still hands the invocation string to a login shell, so the interior remains live, and `$( )`/backtick inside a single-quoted PS literal are inert *as long as the value stays inside the quotes*. The model is sound; the operational consequence the plan must carry (Amendment A4 note) is that **every newtype constructor over PS values must be fallible** (`Result`), because both quoters refuse rather than sanitize — a `From<ValidatedArg> for PowerShellScript` that cannot fail would silently drop that refusal.

**Conclusion: the class statement is structural and survives.** The three properties (private-field newtype, allowlist validation at the seam, non-public raw sink) mirror, in the adapter layer, exactly the confinement `script_template.rs:101-110` already proves compile-enforceable (private `ScriptTemplate` field, no constructor, backstop test at :109-110, `RawFragment` confined by a private-field type verified via E0603 at :84-85). The plan is proposing the already-proven pattern, one layer out.

---

## §3 Attack: the option ranking

The plan ranks A (argv-only, `-EncodedCommand`/remote decoder) as not the first move, B (seam + newtypes + validators) RECOMMENDED, C (per-site escaping) rejected. Attacked from sshd semantics:

sshd re-parses the post-host command string with the account's login shell (`$SHELL -c`), so client-side argv never survives as remote argv — this is QH-13's established sink fact, and it means **"argv-only" at the client is a fiction for SSH**: any argv you pass is re-joined and re-parsed remotely. Option A's real content is therefore "make the remote end decode an unambiguous encoding" (base64 `-EncodedCommand`, or a remote-side decoder), which is a *protocol* change on every guest, not a client-side boundary — correctly not the first move, and strictly more invasive for equal security at the boundary.

Is B the most secure *workable*? Yes, and for a reason the plan under-argues: B's allowlist validates **which commands may run** (command *names* at the seam), not merely that values are inert. A is only a quoting discipline — it guarantees injection fails, but says nothing about `rm -rf /` arriving as a perfectly-quoted word. B inherits the exact-match argv-grammar model of `rustynetd/src/privileged_helper.rs::validate_request` (:1881 — verified: per-program validators, MAX_ARGS, MAX_ARG_BYTES, empty-element refusal, exact token schemas), which is the repo's canonical privileged-boundary control and the one `SecurityMinimumBar.md:238` mandates ("argv-only command invocation with strict input validation"). C is correctly rejected: QH-01's whole lesson is that per-site escaping is the bug class, not the fix.

One sharpening the review adds: B and A are not rivals but phases. B's newtypes should be designed so a later A migration (per-sink EncodedCommand transport) is a change *inside* the seam, invisible to call sites. The plan's `PowerShellScript` over `run_remote_ps` already has this shape; recommend stating it as an explicit design goal (A4 note).

---

## §4 Attack: the validators

For each value class the plan implies, the exact allowlist and its attack surface (all against the verified anchors):

- **ip** — `validate_ip_arg` exists at exactly the three sites the plan names (`linux_traffic.rs:1036`, `macos_traffic.rs:659`, `windows_traffic.rs:989`) with rejection tests at :1599-1615, :945-968, :1715-1726 (the plan cites a subset; all verified). Strict dotted-quad parse ⇒ no unicode, no dash, no `..`, no spaces, no metachars. **Sound.** Risk: three divergent copies is the plan's own structural evidence (:27, verified) — hoisting must pick one semantics, and the test at each old site must move with it.
- **node_id** — plan's implied alphabet `[A-Za-z0-9._-]+` matches `Binding::Bare`'s enforced alphabet exactly (`script_template.rs:215-237`, verified: ascii-alphanumeric + `._-`, empty refused). Leading `-` is *allowed* by that alphabet — for a `Bare` (unquoted) position that is safe because the renderer emits it as a bare word the script never `getopt`s; if the newtype reuses the alphabet for values that DO reach a remote getopt boundary, `-`-leading values become option injection. The seam must own the position, not just the alphabet.
- **path** — `validate_windows_path` (`windows_install.rs:1077`, tests :1655/:1660/:1665 — verified) rejects empty/NUL, accepts normal; shape-only. **Insufficient alone** (see §2.2): must add confinement. POSIX-side there is no shared path validator at all in the adapter layer.
- **utun** — `validate_utun_name` (`macos_install.rs:692`, tests :1900/:1912 — verified) covers the macOS case. Linux interface names have **no** adapter-layer validator here (the repo has `is_safe_interface_name` in `recover_guest_network.rs`, test-pinned at :790 against `"a;rm -rf"` and spaces — reuse it; do not invent a second).
- **service / alias / cidr** — the plan implies these classes but no adapter-layer validators exist for them today. `cidr` in particular: the privileged-helper precedent (:5883 `validate_request_rejects_cidr_field_with_shell_metacharacters`) shows the schema shape to copy.

**Missing classes (Amendment A4):** (1) **connection user** — `User={u}` at `ssh.rs:423` (see A2: the plan's "~:425" is two lines stale; the verified element is `cmd.arg("-o").arg(format!("User={u}"))` in the scp builder, ~:410-426, `scp -P` at :417). Argv-safe, but OpenSSH option values are newline-sensitive config syntax — a `\n` inside a user value starts a new `ssh_config` option line (option injection, e.g. `ProxyCommand`). Source is operator/inventory (`NodeConnection`), so severity is low, but the plan's "SAFE-BY-CONSTRUCTION (weak)" verdict is argv-only reasoning; the correct statement is "safe against shell injection, unguarded against ssh option-line injection." (2) **bundle filenames** — `distribute_signed_bundle`/`distribute_verifier_key` take `&Path` and are scp targets (scp remote paths are remote-shell words). (3) **service names** (`windows_install.rs` constants today — pin them as consts at the seam). (4) **ports**. (5) **interface names** (Linux, per above).

---

## §5 Attack: the migration order

Leaf-first (argv-join → traffic → install/membership → flip signatures) is the right dependency direction, and the plan's own §7 sizing matches it. Two attacks:

**1. Dual-sink window.** Between the first leaf migration and the final signature flip, both raw and typed sinks are live, and a new call site can pick the raw one. This is unavoidable in an incremental migration and the plan's Step-5 source-scan pin is the correct backstop — **provided the pin lands in the same commit as the first migration, not after the last**. Amendment A7 tightens this.

**2. Is the final flip compiler-enforceable?** Only if the old `run_remote*` functions are **deleted** in the flip commit, not deprecated. The repo's own rule (AGENTS.md §3: one hardened execution path, no legacy branch) requires deletion; a `#[deprecated]` stub keeps the raw sink public and the source-scan gate load-bearing forever. The flip is enforceable *by the compiler* exactly when the last caller migrates and the raw fn is removed in the same change — at that point any new raw call site fails to compile, which is strictly stronger than the gate. Recommend the plan state "delete, don't deprecate" explicitly.

**3. Test bypass.** The QH-01 review block (verified at `QualityHardeningTodo_2026-07-25.md:53-100`, verbatim quote in plan :37) records that 18 of 50 `.replace("__` hits were inside `#[cfg(test)]` modules re-implementing the render chain locally. The same failure mode applies to the source-scan test: production sinks may move while tests keep passing against local re-implementations. The scan must run over non-test code and the tests must be *bound to the seam* (QH-13's mutation-verified pattern: assert on the real lowering function, not a local copy).

---

## §6 Attack: the CI gate

The proposal (gate binary in `rustynet-cli/src/bin/` + `scripts/ci/` wrapper mirroring `secrets_hygiene_gates.sh`) has working precedent: both wrapper targets exist and follow the thin-wrapper-over-Rust-binary pattern (`scripts/ci/secrets_hygiene_gates.sh`, `scripts/ci/check_backend_boundary_leakage.sh` — verified present). Conflict check: **no overlap** with `check_backend_boundary_leakage.sh` (different boundary — crate imports vs sink syntax) and **no conflict** with the QH-12/QH-13 controls (`ensure_single_quoted_script_value` at `mod.rs:3174` and the `remote_command_string` chokepoint) — but the gate must *state* that precedence, or a future edit will "satisfy" the new gate by removing the QH-12 defence-in-depth guard the plan's own §6 forbids weakening.

**Precision requirement (Amendment A7):** the rule must exclude `#[cfg(test)]` regions. QH-01's evidence: the grep-based predecessor mis-fired on tests 18/50 times. A syntax-aware exclusion (or a documented allowlist of test modules, audited like the privileged-helper allowlist corpus at `privileged_helper_allowlist_audit.rs:120`, whose adversarial-plus-benign corpus and mislabel-regression test at :412-459 are the repo's model for "the gate must fail if the allowlist regresses") is the difference between a gate and a no-op. Dispatch precedent verified: `rustynetd/src/main.rs:326` routes `privileged-helper-allowlist-audit`; regression tests with shell-like token rejection (`"$(id)"` etc.) sit at `privileged_helper.rs` ~:5486-5500.

---

## §7 Attack: the live-proof mapping

The plan's §7 stage-to-path mapping was checked against the ledger. **`windows_stage_bootstrap` = 5 fail / 0 pass is exact** in `documents/operations/live_lab_node_run_matrix.csv` (242 data rows; quote-aware parse: 5 `fail`, 237 `not_run`, 0 `pass`). The plan correctly cites the live `--node` ledger, not the 550-row frozen bash archive (whose `windows_stage_bootstrap` column shows 66 pass / 8 fail — bash-era evidence, inadmissible per the ledger rule). The blocked-proof reasoning in plan :101 and :113 is therefore sound and correctly refuses dry-run-as-pass.

Two cautions the plan should inherit (both from the standing ledger warnings): `traffic_test_matrix` stage columns have a documented history of masking the stage they are named for — pass/fail claims must come from the stage's own report artifact, never the CSV column alone; and the `macos_stage_*` family in the sizing table is real (the ledger carries those columns) but per-stage pass counts were not re-audited here (§10).

Per-path coverage is otherwise coherent: `traffic_test_matrix` + `live_two_hop_validation` exercise the traffic adapters; bootstrap/membership stages exercise install/membership adapters; the argv-join validators run in every `validate_baseline_runtime`. No adapter path is identified that is untestable without the lab except the Windows ones already blocked — consistent with plan :101.

---

## §8 Anchor audit

Every plan-internal anchor re-opened at `fc6ed568`. Verdicts:

**VERIFIED exactly:** `vm_lab/mod.rs:14` (private `mod script_template;`); mod.rs:35043 `shell_quote` (POSIX single-quote doubling); mod.rs:35056 `powershell_quote` (control-char refusal, returns `Result`); mod.rs:3150-3153 `AllowEmpty`; :3157-3173 QH-12 doc; :3174 `ensure_single_quoted_script_value`; mod.rs:5349+ `run_host_cmd` (fn at :5354, doc comment :5349-5353 — the "+" reading); mod.rs:33833/:33932/:34249 `run_remote_shell_command*`; the four test-name anchors :48095/:51334/:51861/:52507; `script_template.rs` (real path `crates/rustynet-cli/src/vm_lab/script_template.rs`, 3369 lines): :31-38 sink table, :59-99 module contract, :76-93 `RawFragment` private-field confinement, :84-85 E0603 proof, :101-110 boundary + backstop :109-110, :215-237 `Bare` alphabet; ssh.rs:432/:442/:456/:495/:524; windows_install.rs:81-92/:95-100/:104/:122/:132 (plan's :83/:96 are inside the fns — fine) and tests :1366/:1372/:1377; windows_install.rs:1077 + tests :1655/:1660/:1665; sampled sites :225-228/:347/:522/:1067/:1241/:1266/:1346 all consistent with per-site-escaped classification; macos_traffic.rs:350-351 (guard then format — exact); :419 `rm -f '{remote_tmp}'` (exact); windows_traffic.rs:49-51/:561-563/:659-661/:672-674/:700/:937-949 (all ps_quote-guarded or fixed-const as classified; :947 interpolates `issue_subcmd` unquoted but it is a fixed subcommand token); macos_install.rs:692 + tests :1900/:1912; linux.rs:209 and macos.rs:217 sudo-join (verbatim); remote_shell.rs:351; `stage/cross_network/substrate.rs:171` (plan's short path is unambiguous in context); `negative_control.rs:485`; `recover_guest_network.rs:260-278` (renderer-delegation doc block) + test at :790 (`interface_and_user_safety_rejects_injection`); QH-01 review block :53-100; privileged_helper.rs:1881 `validate_request`; allowlist_audit corpus :120 and regression tests :412-459; rustynetd main.rs:326 dispatch; privileged_helper.rs ~:5486-5500 shell-token regression tests; QH-01 §1 claims: zero `script_template` references under `adapter/` (grep-verified), 62 `ps_quote` references in windows_install.rs (exact), `validate_ip_arg` defined 3 times (exact), `shell_quote` in 3 variants (exact: mod.rs:35043, remote_shell.rs:351, substrate.rs:171); ledger claim `windows_stage_bootstrap` 5 fail / 0 pass (exact, live `--node` ledger).

**STALE (minor):** `User={u}` — plan says ~:425; the element is at **ssh.rs:423** (see A2).

**WRONG (must fix):** plan :72 — "The test helper `run_remote_argv` (`negative_control.rs:485`) stays a test-only construct." `run_remote_argv` is **production code**: it sits before the file's first `#[cfg(test)]` (:811) and is called by the negative-control stage at :608/:623/:691/:721. It is genuinely out of scope — but because it is argv-only (`RemoteShellHost::run_argv`), not because it is a test. A1 fixes this; the misclassification matters because the Step-5 gate must not learn "test helper" as an exemption category for this symbol.

**Attributed historical quotes (correctly quoted, lines since drifted):** plan :37 and :43 block-quote the QH-01 review, including its "`mod.rs:37993`" escaper location and "`HOST_LAUNCH_SCRIPT` (`:5008`)". Those were true when the QH-01 review wrote them; today the escaper is at `mod.rs:35043` and `HOST_LAUNCH_SCRIPT` is `const HOST_LAUNCH_SCRIPT: ScriptTemplate` at `vm_lab/script_template.rs:827`. As *quotes* they are legitimate; the plan should add a bracketed "(line since moved)" note so a future reader does not treat them as current anchors. No plan-internal anchor depends on either.

---

## §9 Amendments (exact replacement wording)

**A1 — fix the `run_remote_argv` classification (plan line 72).** Replace the sentence:

> "The test helper `run_remote_argv` (`negative_control.rs:485`) stays a test-only construct."

with:

> "`run_remote_argv` (`negative_control.rs:485`) is production code in the negative-control stage (called at :608/:623/:691/:721, before that file's first `#[cfg(test)]` at :811) and is out of scope because it is **argv-only** (`RemoteShellHost::run_argv`), not because it is a test. The Step-5 gate must not treat `run_remote_argv` as a test exemption; it is simply not a string sink."

**A2 — correct the `User={u}` anchor and complete its threat statement (plan line 23).** Replace "`(~:425)`" with "`(ssh.rs:423)`", and in §8 question 4, after "inject option syntax", add:

> "The concrete mechanism is newline-based: OpenSSH option values are config-line syntax, so a `\n` inside the user value starts a new `ssh_config` option line (e.g. `ProxyCommand`). Add a `ValidatedArg::connection_user` class with a strict alphabet (no control characters, no whitespace beyond the inventory's documented shape) applied where `NodeConnection` feeds `base_ssh_command`."

**A3 — reclassify `macos_traffic.rs:419`.** Replace the verdict cell "**QUOTED (partial)** — :419 is the weakest audited site" with:

> "**QUOTED (partial)** — :419 is the weakest *guarded* site, not the weakest *exposed* one: `remote_tmp` is the compile-time const `/tmp/rn_diag_artifacts.tar.gz` (`macos_traffic.rs:398`), so there is no live injection today; the risk is regressive (a future parameterization of `collect_artifacts` would inherit an unvalidated hand-quoted interpolation). Migrate it with the traffic batch, not as the priority driver."

**A4 — complete the validator class list (plan §4).** After the `utun` class, add: `connection_user` (A2), `interface_name` (reuse `is_safe_interface_name` from `recover_guest_network.rs` — test-pinned at :790 — rather than a new validator), `bundle_filename`, `service_name` (pin the existing `windows_install.rs` constants), `port`. State two binding rules for the newtypes: (1) every PS-side constructor is fallible (`Result`) because `ps_quote`/`powershell_quote` refuse rather than sanitize; (2) `ValidatedArg::path` pairs shape validation with confinement (per `script_template.rs:38`, quoting cannot contain a path). Add as a design goal: the newtypes must let a later Option-A transport migration (per-sink `-EncodedCommand`) happen inside the seam without call-site changes.

**A5 — add the Windows argv-join analogue to the UNQUOTED-RISK family (plan §1).** Add a row: `windows.rs:329-345 build_validator_script` — binary path ps_quote'd, remaining validator argv emitted via `rest.join(" ")` (:342) unquoted into the PowerShell string; elements are fixed-safe strings from `WindowsDaemonProbe::build_argv` today (same by-construction safety as the sudo joins); must be included in the Step-4 signature flip or Windows ends half-migrated.

**A6 — cite QH-13 as the seam precedent (plan §2/§3).** Add: "QH-13 (CLOSED 2026-08-29, commits `496bf2fb`, `cd573224`) established the seam pattern for the argv-shaped sink: `remote_command_string` at the `run_host_cmd` chokepoint, mutation-verified tests bound to the seam, and an explicit scope note that the whole-script family (this plan's subject) was left open. This plan is that item's designated successor for `adapter/`; it should reuse the pattern (seam fn + tests bound to the real lowering, not local re-implementations) and cite the closure."

**A7 — CI-gate precision (plan §5).** Add to the gate spec: (1) the scan rule excludes `#[cfg(test)]` regions (QH-01 precedent: 18/50 grep hits were in-test re-implementations); test-only fixtures live under `#[cfg(test)]` and are audited, not blanket-allowed; (2) the gate states its precedence against the QH-12 guard (`ensure_single_quoted_script_value`, `mod.rs:3174`) and the QH-13 chokepoint (`remote_command_string`) — satisfying this gate must never justify removing either; (3) the allowlist of deliberate exemptions is adversarially audited in the style of `privileged_helper_allowlist_audit.rs` (corpus + mislabel-regression test, :120/:412-459).

**A8 — answer plan §8 question 5 (blocked-Windows proof).** Keep the §7 4c wording (line 101) and add the explicit policy: "Until `windows_stage_bootstrap` is green, Windows migration evidence may be recorded as unit-level + local Windows coverage **only if** (a) every such artifact is explicitly marked non-live, and (b) the dependency is recorded in the parity ledger (`CrossPlatformRoleParityRefresh_2026-07-23.md`). The parity mandate (per-role × per-OS live proof) remains unmet for the Windows migration until the stage passes live; a green unit suite never substitutes for the live cell."

Additionally (editorial, non-blocking): add a bracketed "[line since moved — current: `mod.rs:35043` / `script_template.rs:827`]" note after the two block-quoted historical anchors in §2 (plan :37, :43), per §8 above.

---

## §10 What could not be verified

1. **No live lab.** This review ran in an isolated worktree with no VM access exercised; the ledger was read, not extended. Per-stage pass counts for `macos_stage_*` beyond the `windows_stage_bootstrap` count were not re-audited row-by-row.
2. **PowerShell 5.1 vs pwsh metacharacter exactness** (plan §8 question 3) — not resolvable without running both interpreters; the review confirmed the quoting model's *static* soundness only.
3. **The plan's per-site "QUOTED" verdicts** for all 62 `ps_quote` references were sampled (:225-228/:347/:522/:1067/:1241/:1266/:1346, plus the verified helper sites), not exhaustively re-read; the count itself is exact.
4. **The D-reader semantics of `run_remote_retrying`'s `ReadOnlyProbe` marker** (plan §8 question 2) — the fn exists at `ssh.rs:495`; its marker semantics were not chased in this review.
5. **Behavior under a hostile inventory** (`NodeConnection` fields beyond `user`) — reviewed statically; no fuzzing or payload execution was performed, consistent with the docs-only scope.
