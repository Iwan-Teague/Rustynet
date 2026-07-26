# QH-01 — Structural fix for the host-script template-injection class — 2026-07-25

**Owner:** WS-D. **Status:** PLAN — pre-build, pre-adversarial-review.
**Register:** `QualityHardeningTodo_2026-07-25.md` QH-01 (P1, high, privileged
boundary), taking QH-12 with it (the register names QH-12 as QH-01's precondition).
**Scope note:** QH-03 (fail-open script shape) is **adjacent but deliberately NOT in
this plan** — see §6; its true scope is larger than the register states.

## 0. STATUS UPDATE (2026-07-26) — QH-13 is CLOSED; read this before §10/§11

This document was written while `QH-13` (validate-for-the-sink / SSH post-host argv)
was still open, and it says so in several places below — **those statements are now
stale**. `run_host_cmd` builds its remote command through `remote_command_string`,
which `shell_quote`s every argument, so the sink is safe independently of what any
caller validated. Both values this document names as exposed are covered: `pool`,
and the stdout-derived `device` (which additionally gets an
`ensure_no_control_chars` check at capture, because it is printed to the operator).

The claim was also upgraded from INFERRED to **confirmed**: `ssh(1)` states that
arguments "will be appended to the command, separated by spaces, before it is sent
to the server to be executed", and an adversarial review then executed the pre-fix
payload against a real lab host and observed remote command execution, followed by
the post-fix payloads arriving as literal text.

Specific stale lines, left in place because §2's own norm is to correct the record
rather than delete it: §5 ("until QH-13 lands"), §6 (INFERRED), §10's "remain
**open under QH-13**", and §11's "QH-13 untouched". Read them as historical.

Not closed by that work, and still open: `run_host_cmd`'s siblings are fine, but
the empty-args fail-open is now an error rather than a silent login shell, and
`run_host_reboot` — a dead second copy of the SSH transport options with no
`BatchMode`, no `StrictHostKeyChecking`, no pinned `known_hosts` and no `--`
separator — was deleted rather than repaired.

## 1. Independent reproduction (the register's own norm: a finding is not a finding until reproduced)
QH-01 is **CONFIRMED** against `crates/rustynet-cli/src/vm_lab/mod.rs` at local
`main` (`f9388393`). All three legs verified by reading the code:

1. **Substitution order** — in `execute_ops_vm_lab_provision_guest` the chain is
   `__POOL__` → `__NAME__` → `__IMAGE__` → `__DISK_GB__` → `__RAM_MB__` → `__VCPUS__`
   → **`__AUTH_KEY__` last** (`mod.rs:6517-6524`).
2. **A substituted value carries single quotes by construction** — on the
   `Some(path)` branch `auth_key = format!("'{path}'")` (`mod.rs:6514`). (The `None`
   default is double-quoted and inert, so the breakout requires `--authorized-key`.)
3. **The validators permit the literal token text** — `ensure_provision_guest_name`
   (`mod.rs:6304-6320`) allows ASCII alphanumeric + `-` + `_`, so **`__AUTH_KEY__` is
   itself a valid guest name** (uppercase is `is_ascii_alphanumeric`, `_` explicitly
   allowed, 12 chars ≤ 60, doesn't start with `-`). `ensure_script_safe_value`
   (`mod.rs:~5040`) refuses only `"`, `$`, `` ` ``, `\` — not `_`, not uppercase, not
   `'` (the single-quote rule is a *separate hand-rolled* check at each call site).

**Mechanism:** `--name __AUTH_KEY__` passes validation → is substituted into the
script body at the `__NAME__` position (inside a single-quoted literal) → the final
`.replace("__AUTH_KEY__", "'<path>'")` then rewrites *that* text, injecting single
quotes into the name's own quoting context → breakout → command execution on the lab
host. `render_host_launch_script` (`mod.rs:5760-5777`) has the identical shape
(`__REPO_DIR__`/`__REPORT_DIR__`/`__LAUNCH_ID__` before `__ORCH_IDENTITY__`/
`__ORCH_KNOWN_HOSTS__`/`__ORCH_ARGS__`, the latter three quote-carrying).
Both sites are reachable from the CLI **and** from `rustynet-mcp-lab-state`
(`provision_guest`, `launch_live_lab_on_host`) — the confused-deputy exposure in
`HostObservabilityStabilityPlan_2026-07-24.md` §7.10.

## 2. Corrections to the register (record, do not delete — QH-06/QH-07 norm)
- **QH-12 is STALE/WRONG as written.** It claims *"A shared helper composing the
  metacharacter check with the single-quote rejection now exists, and two sites use
  it — but 8 hand-rolled copies remain."* Verified: **`ensure_single_quoted_script_value`
  does not exist** — 0 occurrences in `vm_lab/mod.rs` on **either** local `main` or
  `origin/main`. The nearest thing is `ensure_orchestrator_arg_safe` (`mod.rs:5067`),
  which is scoped to orchestrator args, not a general single-quoted-value helper. And
  there are **10** hand-rolled `contains('\'')` call sites, not 8
  (`mod.rs:5069, 5262, 5541, 5545, 5719, 5826, 5830, 5851, 5865, 6511`). So QH-12 is
  not "finish the last 8" — the canonical helper must be *created*, and all 10 sites
  converted.
- **QH-03 scope is understated.** The register marks it *"VERIFIED for the
  provisioning script; other scripts UNAUDITED."* Verified: **10** host scripts use
  `set -uo pipefail` (no `-e`) and only **1** uses `set -euo pipefail`, on both local
  `main` and `origin/main` (15 `const *_SCRIPT` total). The fail-open shape is
  near-universal in this file, not a single-script defect.

## 3. The fix — v2: the renderer OWNS THE QUOTING (escape-first)
**Superseded design (v1, refuted — kept visible per the register's norm):** v1 chose
only the single-pass renderer, treating this as an *ordering* bug. The adversarial
review (§9) refuted that: **two breakouts on the same script need no ordering at all**
— `pool` is unvalidated and `image` is validated only for path-shape, so
`--pool ".../images';touch /tmp/x;'"` and `--image "d.qcow2';id;'"` break out of
`POOL='__POOL__'` / `IMAGE='__IMAGE__'` byte-identically under v1's renderer. Order-
independence is **necessary but not sufficient**.

**v2 = escape at interpolation is the load-bearing control; rejection is the extra.**
The escaper already ships in this very file: `shell_quote` (`mod.rs:37993`, POSIX
`'` → `'\''`), used **110×** here. The templated half is precisely the half that
doesn't use it.

1. **Typed bindings** — the renderer, not the caller, decides quoting:
   - `Literal(v)` → renderer emits `shell_quote(v)`. **The template must NOT wrap the
     token in quotes** (`POOL=__POOL__`, not `POOL='__POOL__'`).
   - `Bare(v)` → renderer enforces `[A-Za-z0-9._-]+` (numerics, `__CAP__`, `__CHANNEL__`).
   - `RawFragment(v)` → verbatim, for the bindings that are shell syntax **by
     construction** (`__ORCH_ARGS__` is pre-joined `'a' 'b'`, `mod.rs:5768-5772`; the
     `$HOME`-bearing defaults at `:6508`/`:5848`/`:5862`). Each site carries a comment
     naming its enforcement + proving test (QH-05).
   *(Why this matters beyond safety: the same token has different quoting contexts
   across templates — `__POOL__` is double-quoted at `:3978` but single-quoted at
   `:5213`/`:6564`; `__REPO_DIR__` appears single- AND double-quoted on one line
   (`:4983`). A validator named for the value cannot be right for both; the renderer
   can. Also: a uniform validator would REJECT the `$HOME`-bearing defaults, breaking
   `launch_on_host`/`provision_guest` on their default paths — which is why the
   fragment split is mandatory, not stylistic.)*
2. **Single-pass walk** — still built (order-independence is necessary): substituted
   bytes are never re-scanned. Fail closed on **an unconsumed declared binding**.
   **Do NOT error on an unknown token found in the template** — `__PLACEHOLDERS__`
   occurs in a comment (`:5008`) and `__VM_LAB_SECTION__`/`__RUSTYNET_CAPTURE_*` are
   protocol sentinels; that rule would break every launch (§9 B3).
3. **Scope — all render sites, including the two the review added:**
   - `vm_lab/mod.rs`: the **32 production** `.replace("__` sites (18 of the 50 are
     inside `#[cfg(test)]`; converting those is not the work — see §4).
   - **`vm_lab/recover_guest_network.rs:276/292/309`** — repair scripts piped to
     **`sudo bash -s`** (root-privileged, `:395`). Note `netplan_repair_script` (`:259`)
     interpolates a multi-line YAML body into a heredoc whose terminator only works
     because the body ends in `\n` — the correct rule there is "no line equal to the
     terminator", which is neither helper. Handle explicitly.
   - The two `format!`-assembled scripts (`build_section_capture_script` `:39503`,
     `privileged_rustynet_cli_script` `:39487`) are inert today (all call sites pass
     `&'static str`) — **pin that with a test** rather than leaving it unstated.
4. **`pool` and `image` MUST be in scope** (§9 B1) — otherwise §5's acceptance is
   satisfiable while `provision_guest` stays remotely exploitable. `pool` gets a
   validator (it has none today); `image` gets paired with the metacharacter check the
   way `fetch_image` already does correctly (`:4302-4303`).
5. **QH-12:** create the canonical `ensure_single_quoted_script_value(label, value)`
   and convert all **10** hand-rolled sites — but note that after v2 most `Literal`
   values no longer *need* a single-quote rule (escaping subsumes it); the helper
   remains for `RawFragment`/pre-quoted paths. Needs an explicit `allow_empty`: three
   bindings are legitimately empty (`__SHA256__`, `__EXPECT_MODEL__`, `__TARGETS__`)
   and `ensure_no_control_chars` rejects empty (`:37960`); `Literal("")` →
   `shell_quote("")` = `''` is legal and must stay legal (§9 M2).
6. **Enforcement boundary instead of a grep** (§9 S4): wrap templates in a
   `ScriptTemplate(&'static str)` newtype whose only consumer is the renderer, and move
   the script consts + renderer into a `vm_lab::script_template` module with the consts
   private. A new render site then *cannot compile* a bypass. The `.replace("__` grep is
   evadable (`replacen`, `format!`, a variable token) and fires on legitimate test code
   and on `recover_guest_network.rs` — keep a grep only as a backstop, for
   `const [A-Z_]*SCRIPT` declared outside the module.

## 4. Tests — v2 (per QH-02; v1's assertion was refuted as imprecise)
v1's "assert the rendered script is inert / no additional `'` in that value's context"
is **not mechanically checkable**, is undefined for `__ORCH_ARGS__` (which *must* add
`'`), and would **pass** on breakout `--image "d.qcow2';id;'"` (the payload leaves the
line's quote count where a naive expectation puts it). `bash -n` is near-worthless too:
`IMAGE='d.qcow2';id;''` is syntactically valid. Four pieces instead (§9 S3):

1. **Real-call-path negative tests via `dry_run` (this is the QH-02 piece).** Both
   vulnerable entry points return *after* validation and *before* any SSH —
   `execute_ops_vm_lab_provision_guest` at `:6424-6446`, `execute_ops_vm_lab_launch_on_host`
   at `:5881-5896`. With a temp inventory (`write_temp_inventory`, `:41770`) and
   `dry_run: true`, assert `Err` for hostile `--pool` / `--image` / `--name` /
   `--authorized-key` / `--report-dir` / orchestrator args. **Deleting a validation
   call turns these red** — which a pure-render-helper test cannot do. (Confirmed
   necessary: `cargo test … --lib provision` is 9/9 green *today*, with both breakouts
   live.)
2. **Byte-for-byte expected rendering**, not `contains(...)` — a full expected string is
   the only assertion a still-vulnerable renderer cannot satisfy, and it doubles as the
   **fails-on-revert** test (an ordered chain yields different bytes on
   placeholder-as-data input).
3. **Structural invariant test over the consts themselves** — this is what catches a
   *new* site: a `(template, declared_tokens)` table asserted exhaustive against a scan
   of each const, **plus** an assertion that no `Literal`-typed token is adjacent to a
   `'` or `"` in its template (that adjacency is exactly the v1 bug class). No call site
   can bypass it.
4. **Tokenizer-level assertion** for placeholder-as-data: assert the rendered script
   parses to the exact expected assignment/argv list, not "looks inert".
- Negative cases from **attack classes**, never the implementation's reject-list
  (quote breakout, `;`/`|`/`&`/redirection, glob, `$`/backtick, newline/heredoc
  terminator, homoglyph, leading `-`/`.`, over-length).
- **Name + test the heredoc control (§9 S2):** `HOST_LAUNCH_SCRIPT` writes a *second*
  script via `<<'RUNNER_EOF'` that `bash` re-parses (`:5010-5017`). A `repo_dir`/
  `report_dir` containing `\n` + `RUNNER_EOF` would close the heredoc early and execute
  the remainder in the **outer** script. The only thing preventing it today is
  `ensure_no_control_chars` rejecting `\n` (`:37963`) — an unnamed, untested,
  load-bearing control. Name and test it.
- **QH-05:** every safety comment touched names enforcement point + proving test. This
  includes **deleting or correcting the false "argv-only (§4)" claim** on `run_host_cmd`
  (`:6627`) — see §5.

## 5. Acceptance — v2 (scoped honestly)
- **Escaping owns the quoting:** no interpolated value can alter any value's quoting
  context, proven by the byte-for-byte + tokenizer tests, for `Literal` bindings.
- **`pool` and `image` are validated** on the `provision_guest` path (they are not
  today), proven by real-call-path `dry_run` negative tests.
- **Deleting any enforcement call turns at least one named test red.**
- **A new render site cannot compile a bypass** (newtype + module boundary), backstopped
  by a grep for `const [A-Z_]*SCRIPT` outside the module.
- All 10 hand-rolled single-quote sites converted (QH-12 closed).
- **SCOPE LIMITATION — stated here and to be mirrored into the register (§9 S5):** this
  change hardens **template rendering**. It does **not** close the second sink:
  `run_host_cmd` (`:6628-6677`) documents itself "argv-only (§4)" but appends post-host
  argv that OpenSSH joins and the remote **login shell re-parses**, and unvalidated
  `pool` reaches it at `:6457-6462` on a path gated by `host.pool_disk_model` —
  which `ubuntu-kvm-1` declares (`vm_lab_inventory.json:21`), so **the path is live on
  the real lab host**. Worse in kind, `:6472-6477` passes `device`, derived from the
  previous command's **remote stdout** → remote output into remote argv. QH-01 must NOT
  be recorded as "the injection class is closed" — `provision_guest` is not hardened
  until QH-13 lands (right fix there is again escaping: build the remote command from
  `shell_quote`d words, or drop the false comment and validate for a shell).
  Mitigation inside this change: `pool` gains a validator, which reduces (does not
  eliminate) that exposure.

## 6. Explicitly NOT in this change
- **QH-03** (`set -e` / fail-open script shape, 10 sites) — adding `-e` changes host
  operation behaviour (steps currently tolerated would start failing runs) and needs
  its own audit + per-step decision + lab validation. Doing it inside a security fix
  would conflate a hardening change with a behavioural one. Separate item; its
  corrected scope is recorded in §2.
- **QH-13** (validate-for-the-sink / SSH argv) — INFERRED in the register, not
  reproduced; needs a non-destructive marker confirmation first, and must not be
  injection-tested against a shared lab host.

## 10. BUILD OUTCOME (2026-07-25) — built + gated, integration pending
Branch `claude/wsd-qh01`, base `e171e5c7` (= `origin/main` + cherry-picked `f9388393`),
commits `a94468c7` (renderer) + `89d35a37` (convert every site). **Not pushed.**
Adversarial review of the *built code* was in flight at time of writing; integration and
the register close-out follow it.

**Built:** new module `vm_lab/script_template.rs` (~2.4k lines incl. relocated templates
and 18 tests). `render_script_template(ScriptTemplate, &[(&'static str, Binding)])` —
single pass, never re-scans emitted bytes, fails closed on an unconsumed binding, and
deliberately does **not** error on an unknown `__TOKEN__` (§9 B3). Bindings:
`Literal`→`shell_quote`, `Bare`→charset, `QuotedWords`, `RawFragment` (`&'static str`-typed
so caller data cannot reach it), `HeredocBody{value,terminator}`, `PowerShellLiteral`.

**Scope achieved:** all **32 production + 18 test** render sites converted, including the
3 root-privileged `sudo bash -s` repair scripts in `recover_guest_network.rs`.
`grep -rn '.replace("__' crates/rustynet-cli/src/` now matches only a doc comment
*(verified independently)*. `ScriptTemplate(&'static str)` has a **private field and no
`impl` block** — no constructor exists, the renderer and every template const are private,
so a bypass **cannot compile** *(verified)*. Backstop is a Rust `#[test]` scanning for raw
strings carrying `__TOKEN__`, not an evadable grep.

**Deviations from §3, both strengthening (flagged, not silent):** `QuotedWords` replaced
`RawFragment` for `__ORCH_ARGS__` and the `Some(path)` override branches, so
`format!("'{path}'")` — the quote-carrying-by-construction value at the root of this bug —
is **gone entirely**; and `HeredocBody`/`PowerShellLiteral` were added so the netplan YAML
and the PowerShell site cross the same boundary.

**Three defects found during the build that the plan had not anticipated:**
1. The planned `image` fix was **insufficient** — pairing with `ensure_script_safe_value`
   (as `fetch_image` does) still accepts `;`, `|`, `&`, `>`. Caught *because* the
   attack-class list included `x;id`. Converted to a real allowlist.
2. `authorized_key` validation sat **below** the dry-run return — unreachable on that path.
   Hoisted.
3. Latent bug: `ensure_script_safe_value("pool_disk_model", "")` rejects empty, so
   `fetch_image` failed outright on any host declaring no `pool_disk_model`. Fixed via
   `AllowEmpty`.

**QH-12 closed** by *extending* `ensure_orchestrator_arg_safe` into the canonical
`ensure_single_quoted_script_value(label, value, AllowEmpty)` — not a fifth idiom — with
all 9 hand-rolled sites converted and `:5069` (the helper body) correctly left alone.

**QH-02 partially closed:** 10 real-call-path `dry_run` negatives, and **mutation-verified**
— deleting each of 9 enforcement calls in turn turns exactly one named test red. Honest
gap recorded in-code: the `repo_dir` guards in `fetch_host_artifact`/`stop_host_run` have
no `dry_run` path, so their control is the renderer's escaping.

**QH-05:** the false `argv-only (§4)` comment on `run_host_cmd` was **corrected, not
deleted** (now quotes the real OpenSSH behaviour, names `pool` and the stdout-derived
`device`, points at QH-13); the two "every interpolated value is single-quoted…" comments
were false in exactly the way QH-05 describes and now record what they used to say and why.

**Gates — re-run independently by the reviewer, not taken on trust:** default (no-feature)
`cargo check` clean (the cfg-gating trap avoided); `--features vm-lab` clean;
`cargo test --lib` **2172 passed / 0 failed** (+34, none removed); `fmt` clean;
`clippy --all-targets` **0 warnings/errors** — run with **no `--exclude rustynet-mcp`**,
per the QH-06 finding verified this session.

**Scope limit restated:** `pool`'s script sink is closed, and its SSH-argv sink is closed
**for `provision_guest` only**. `run_host_cmd` itself, its other call sites, and the
stdout-derived `device` remain **open under QH-13**. No `set -e` added (QH-03 out of scope).

## 11. Adversarial review of the BUILT code (2026-07-25, opus) — HELD, not integrated
**Verdict: safe to integrate, no blockers. The verified injection class IS closed for the
converted sites** — the reviewer could not construct a surviving payload via a mis-escaped
`Literal`, a still-quoted template site (none exist, verified mechanically), a doubly-bound
token, `QuotedWords` joining, heredoc-terminator smuggling, a `Bare` charset gap,
newline/`#`/`\0`, or an empty value. Single-pass walk confirmed correct (emitted bytes never
re-scanned); `shell_quote` POSIX-correct; **all four bind-once template rewrites confirmed
behaviour-preserving** (mechanical old-vs-new diff of all 14 bodies: only token un-quoting
plus the four rewrites; each var assigned unconditionally so `set -u`-safe when empty, and
double-quoted at every use); module boundary holds; QH-13 untouched and not weakened.

**BUT: three safety claims in the new code are false or unenforceable — the exact QH-05
failure mode this change exists to eliminate. So the work is HELD in the worktree and
QH-01/QH-12 are NOT recorded as "closed with evidence" until these are corrected:**
- **S1 — a `Literal` is re-parsed by a nested shell.** `HOST_GUEST_CONSOLE_SCRIPT`
  (`script_template.rs:456`) passes `$DOM` through `script -qec` → `$SHELL -c`, so the
  value is re-parsed as a command *string*; `shell_quote` at the assignment buys nothing
  there. **Not exploitable today** — the sole control is `ensure_provision_guest_name`
  (`[A-Za-z0-9_-]`, ≤60) — but that control is unnamed at the template, `guest_console` has
  no `dry_run` so **no test goes red if it is deleted**, and the adjacency invariant cannot
  see it (it inspects the token site, not the `$DOM` use). Fix: `DOM="$DOM" … script -qec
  '… --console "$DOM"'`, plus the enforcement-point/proving-test comment. This is the one
  place "the renderer owns the quoting" is **not** sufficient and must be stated as such.
- **S2 — `build_section_capture_script`'s stated compiler control does not exist.** Its doc
  says both the section name and its body are `&'static str`; the **body is `&str`**, and
  `mod.rs:31088` already passes a runtime `String`. The backstop test cannot detect a
  violation (its local coerces by covariance, pinning nothing).
- **S3 — `RawFragment`'s "can only ever be a compile-time literal" is false.**
  `&'static str` ≠ literal (`String::leak`), and `HostSshPath::Default(&'static str)` is
  `pub(crate)`, so the one binding with **zero** validation is constructible crate-wide.
  Not caller-reachable today, but it weakens "a bypass cannot compile".

Also: **S4** the structural invariant is table-driven with no assertion that the table is
complete/faithful (a new template silently escapes it); **S5** the backstop scanner misses
`r"…"`, plain `"…"`, lowercase tokens, `replacen`, and variable tokens; **S6** the disclosed
coverage gap is incomplete (also uncovered: `fetch_image` pool/url/image,
`host_disk_status` pool, `fetch_host_artifact` path, **`guest_console` domain — the S1
site**, `recover_host_vms` domain, `provision_toolchain` channel). Minors: `Bare` permits a
leading `-`/`..` (option-injection only, and interface names are remote-guest-derived);
`scan_tokens` panics on `__` + a multi-byte char; stale test doc claiming a second net for
`image`; the golden's fails-on-revert claim is overstated (the real ones are
`rendering_is_single_pass_…` and `a_guest_name_spelling_another_token_stays_data`);
`PowerShellLiteral` skipped by the adjacency invariant; heredoc terminator triplicated with
no invariant; `pool` now has two rules in one file (strict in `provision_guest`, loose in
`fetch_image`/`host_disk_status` — all sinks escaped, so no injection).

**Gate note:** the reviewer measured **2171 pass / 1 fail** — the failure is
`execute_ops_vm_lab_discover_local_utm_skips_inventory_update_when_no_live_ip_observed`, a
>100 s local-UTM/`utmctl` test that **passes in isolation** and whose subject appears **0
times in the diff**. An unrelated timing flake, not a regression. (My own full-suite run
was 2172/0.)

**State:** branch `claude/wsd-qh01` @ `89d35a37`, built, gated, adversarially reviewed,
**not pushed**. Next session: correct S1–S3 (+S4–S6 and the minors as judged), re-review,
then integrate ff and close out QH-01/QH-12 in the register with evidence.

## 9. Adversarial review of the PLAN — incorporated (2026-07-25, opus)
Verdict: **needs changes first** — v1's mechanism did not close the class it claimed
to. Every load-bearing finding re-verified by the author against the code before
rewriting (§3/§4/§5 above are the result):
- **B1 (blocker):** `pool` has **no validator at all** (`:6390-6393` → `POOL='__POOL__'`
  at `:6564`) and `image` is path-shape-only (`ensure_provision_image_name` `:6323`
  permits `'`, `;`, `$`; called alone at `:6372`, unlike `fetch_image` at `:4302-4303`).
  Both break out **order-independently**, so v1's renderer was byte-identical on them.
  *Verified.* Note this is worse than QH-02's wording: there is **no pool validation
  call to remove**.
- **B2 (blocker):** reject was the wrong primary primitive — `shell_quote` (`:37993`)
  already exists and is used 110× in the same file; the same token has different
  quoting contexts across templates, and a uniform validator would reject the
  `$HOME`-bearing defaults, breaking both entry points. → typed bindings, escape-first.
  *Verified.*
- **B3 (blocker):** "unknown token in template ⇒ error" would break every launch —
  `__PLACEHOLDERS__` is in a comment (`:5008`); `__VM_LAB_SECTION__` /
  `__RUSTYNET_CAPTURE_*` are protocol sentinels. → keep only "unconsumed binding ⇒
  error". *Verified.*
- **S1:** site list incomplete — +3 in `recover_guest_network.rs` (piped to
  `sudo bash -s`), 18 of the 50 `mod.rs` hits are `#[cfg(test)]`, and 2 scripts are
  `format!`-assembled (inert today, pin with a test). *Verified.*
- **S2:** `HOST_LAUNCH_SCRIPT` double-parse / heredoc terminator is an unnamed,
  untested load-bearing control. **S3:** v1's acceptance assertion was imprecise and
  existing tests re-implement the render chain locally (so production can change under
  them) — 4-part test shape adopted. **S4:** the `.replace("__` grep is evadable and
  mis-fires → newtype + module boundary. **S5:** the `run_host_cmd` "argv-only" claim is
  false and `pool` reaches it on a live path → scope limitation now written into §5.
  *All verified.*
- **M2** empty-value regression (`allow_empty`), **M3** counts (`set -euo` is 3, none a
  templated host-script const; all **10** bash-body script consts are fail-open — 100%,
  cleaner than "10 of 15"), **M4** cleaner base (below). Confirmed sound and kept: §1's
  reproduction in every particular, the identical shape in `render_host_launch_script`,
  MCP reachability of both sites, rejecting deny-listing `__`, and
  `HOST_FETCH_IMAGE_SCRIPT` as the correct existing model.

## 7. Repo-state hazard — RESOLVED (per §9 M4)
Local `main` (`f9388393`) and `origin/main` (`1c05f518`) have diverged 3/3. v1 proposed
basing on local `main`, which would have required an owner decision because pushing
would also publish WS-B's 2 unpushed **inventory** commits.

**Resolved — no owner decision needed.** The conflict is one-sided: of the 3 local-only
commits only **`f9388393`** touches `crates/rustynet-cli/src/vm_lab/mod.rs`, and **no**
origin-only commit touches it. So the base is `origin/main` + a cherry-pick of
`f9388393` alone. Done: worktree `.claude/worktrees/wsd-qh01`, branch
`claude/wsd-qh01`, HEAD `e171e5c7` — `origin/main` is an ancestor (push stays ff) and
WS-B's inventory commits are **not** on the push path (verified).

## 8. Sequence
Plan (this) → **adversarial review of the plan** → verify findings → build (single-pass
renderer + convert all sites + canonical validator + tests + CI check) → **adversarial
review of the built code** → gates (default no-feature build, `--features vm-lab`,
fmt, clippy, tests) → integrate under the integration token → close QH-01 + QH-12 in
the register **with evidence** (commit + the test that proves it), and record the §2
corrections there.
