# Quality-Hardening TODO — findings from the 2026-07-25 multi-line session

**Status: OPEN. Nothing in this document is implemented unless an item says so.**

> **ADVERSARIALLY REVIEWED 2026-07-25 — read `QualityHardeningTodoReview_2026-07-25.md`
> before acting on any item.** Applying this register's own norm *to the register* found
> **one false retraction (QH-07), three refuted claims (QH-03, QH-12, and QH-02's
> exemplar), four misattributions, and four unrecorded findings.** Every item still
> describes a real defect; the prose around several is wrong. Per-item verdicts are
> inline below, tagged **[REVIEW 2026-07-25]**. Corrected priority:
> **QH-07 → QH-13 → QH-01 → QH-04 → QH-06 → QH-11 → QH-09 → QH-05 → QH-08 → QH-10.**
>
> Two structural lessons for future entries: **name the tree/commit each claim was
> verified against** (several items describe code on `claude/host-observability` or in
> uncommitted worktrees as if it were `main` — that is what produced QH-12's wrong counts
> and QH-05's "history" framing), and **split the confidence label** where mechanism and
> example diverge (VERIFIED-mechanism / REFUTED-example is more useful than one word).
> This register has **15** items, not 13 (`README.md` undercounts).

## Purpose

A register of cross-cutting defects and process weaknesses surfaced while three
work lines ran concurrently on 2026-07-25 (two_hop dataplane, ubuntu-kvm-1 /
WinNAT, host-observability). These are deliberately kept out of the individual
work ledgers because each one spans several files or several lines of work, and
each would otherwise be lost as an aside in a report.

Every item records **what was actually verified** versus **what is inferred**,
because the dominant failure mode this session was confident claims that turned
out to be wrong. Read the confidence field before acting; re-verify anything
marked INFERRED before writing code against it.

## How to use this document

1. Items are grouped by priority, not by area.
2. Take the acceptance criteria literally — several items exist *because* an
   acceptance criterion was satisfiable without the underlying thing being true.
3. When you close an item, record the evidence (commit + the gate or test that
   proves it), not just a status flip.
4. If an item turns out to be wrong, say so in the item and leave it visible.
   Do not delete it — a retracted finding is useful information.

---

## P1 — Do these first

### QH-01 — Eliminate the host-script template-injection class structurally

> **[REVIEW 2026-07-25] Mechanism VERIFIED in every particular. Two corrections, and the
> proposed fix framing was INSUFFICIENT.** Plan + evidence:
> `QH01TemplateInjectionFixPlan_2026-07-25.md`. **Work built and gated; integration
> pending** (branch `claude/wsd-qh01`).
> - **Framing this as an *ordering* bug is insufficient.** Two breakouts on the same script
>   need no ordering trick at all: **`pool` had no validator whatsoever**
>   (`mod.rs:6390-6393` → `POOL='__POOL__'` at `:6564`) and **`image` was path-shape-only**
>   (`ensure_provision_image_name` `:6323` rejects only empty/`/`/`..`/control chars, and
>   was called *alone*, unlike `fetch_image` which pairs it). Verified payloads accepted:
>   `x'; id; '`, `a'$(id)'`, ``debian`id`.qcow2``, `deb$USER.qcow2`, a Cyrillic-е
>   homoglyph, 500 chars, `x;id`, `x|id`, `x&id`, `-leading-dash.qcow2`. A single-pass
>   renderer alone renders these **byte-identically** to the old chain. So the fix had to
>   make the renderer **own the quoting** (escape at interpolation via the `shell_quote`
>   escaper that already existed at `mod.rs:37993`), not merely fix scan order.
>   Order-independence is necessary but **not sufficient**.
> - **This item cites a validator that does not exist** — `ensure_single_quoted_script_value`
>   (see QH-12). It also calls the image check an "allow-list"; it was a **deny**-list.
> - "Fail closed on an unknown token in the template" would **break every launch** —
>   `__PLACEHOLDERS__` appears in prose in `HOST_LAUNCH_SCRIPT` (`:5008`), and
>   `__VM_LAB_SECTION__` / `__RUSTYNET_CAPTURE_*` are protocol sentinels. Only
>   "unconsumed **binding** ⇒ error" is safe.
> - **Site list was incomplete:** +3 render sites in `recover_guest_network.rs`
>   (`:276/292/309`) whose scripts are piped to **`sudo bash -s`** (root), and 18 of the 50
>   `.replace("__` hits in `mod.rs` are inside `#[cfg(test)]` (they re-implemented the render
>   chain locally, so production could change under them).
> - **The `.replace("__` CI grep is the wrong control** — evadable via `replacen`, `format!`,
>   or a variable token, and it mis-fires on tests and on `recover_guest_network.rs`. Use a
>   type/module boundary so a bypass cannot compile.
> - **SCOPE LIMIT — do not record this item as "the injection class is closed."** The fix
>   covers **template rendering**. The SSH-argv sink (`run_host_cmd`), its other call sites,
>   and the stdout-derived `device` remain open under **QH-13**.
**Severity: high (privileged boundary). Confidence: VERIFIED.**

Host scripts in `crates/rustynet-cli/src/vm_lab/mod.rs` are rendered by ordered
`str::replace` chains. Because `replace` substitutes *every* occurrence and at
least one substituted value legitimately contains single quotes, an earlier value
that contains a later placeholder token can inject those quotes into its own
single-quoted literal and break out.

Verified directly:
- In the provision-guest render chain, `__AUTH_KEY__` is substituted **last**
  (after `__POOL__`, `__NAME__`, `__IMAGE__`, and the three numerics).
- `auth_key` is built as `format!("'{path}'")` on the `Some(path)` branch, so it
  carries single quotes by construction. (The `None` default is double-quoted and
  therefore inert — the breakout requires `--authorized-key` to be supplied.)
- All three of `ensure_provision_guest_name`, the image allow-list, and
  `ensure_single_quoted_script_value` permit `_` and uppercase ASCII, so all
  three can carry the literal text `__AUTH_KEY__`.
- `render_host_launch_script` has the identical shape: `__REPO_DIR__`,
  `__REPORT_DIR__` and `__LAUNCH_ID__` are substituted **before**
  `__ORCH_IDENTITY__`, `__ORCH_KNOWN_HOSTS__` and `__ORCH_ARGS__`, all three of
  which carry quotes by construction.
- A reviewer demonstrated execution on both sites (payloads ran; artifacts were
  removed afterwards).

Both sites are reachable from the CLI and from `rustynet-mcp-lab-state` tools
(`provision_guest`, `launch_live_lab_on_host`), which is the confused-deputy
exposure named in `HostObservabilityStabilityPlan_2026-07-24.md` §7.10.

**Do not fix this by deny-listing `__`.** That is tied to today's token names and
re-opens the moment someone adds a placeholder.

Proposed fix — make substitution order irrelevant:
- a single audited render helper that walks the template **once**, substituting
  known tokens and never re-scanning substituted content; or
- shell-quote in Rust at the point of interpolation so no value can affect how
  another value is quoted.
Apply to every host-script render site, not only the two known-exploitable ones.

Acceptance:
- No interpolated value can alter another value's quoting context, demonstrated
  by a test that feeds a placeholder token as data and asserts the rendered
  script is inert.
- A CI check fails if `.replace("__` appears outside the audited helper.

### QH-02 — Security tests must fail when the control is removed

> **[REVIEW 2026-07-25] Convention CORRECT and the mechanism is provable more strongly
> than claimed — but the cited mutation is impossible and the two exemplar tests are
> SWAPPED.**
> - **The cited mutation cannot be performed: there is no `pool` validation call to
>   remove.** `execute_ops_vm_lab_provision_guest` validated only `name` (`:6371`) and
>   `image` (`:6372`); `pool` (`:6390`) was unvalidated entirely.
> - **The mechanism is airtight by static call graph** (stronger than a mutation run):
>   that function has exactly one caller (`main.rs:8756` ← `execute_ops` `:8440` ←
>   `:6734`), and **no test reaches any of them** — so deleting `:6371`/`:6372` left
>   `cargo test -p rustynet-cli --features vm-lab --lib provision` at **9/9 green**
>   (run and confirmed).
> - **The exemplars are the wrong way round.** The praised "attack classes" test is
>   `provision_guest_name_rejects_anything_not_obviously_safe` (`:41729`) — and even it has
>   **no homoglyph and no leading-`.`** case. The criticised reject-list mirror is
>   `provision_image_must_be_a_bare_filename` (`:41756`), i.e. **the image test**, which
>   this item praises.
> - **"Fails on revert" is unfalsifiable as written** — neither test fails when the
>   *enforcement call* is deleted; both fail if the *validator body* is weakened. State
>   which: *"goes red when the enforcement call at `<file:line>` is deleted."*
> - **The acceptance criterion is vacuous today.** "Every control listed in the
>   security-controls catalogue" resolves to `documents/SecurityMinimumBar.md`, which lists
>   **none** of `ensure_script_safe_value` / `ensure_provision_*` / `vm_lab`. Name the lines
>   instead.
> - **Cheaper and stronger than curated mutation testing:** one **real-call-path `dry_run`
>   test**. Both vulnerable entry points return after validation and before any SSH
>   (`:6424-6446`, `:5881-5896`), and `write_temp_inventory` already exists — so a
>   `dry_run: true` test asserting `Err` on hostile input goes red the moment an
>   enforcement call is deleted, with no harness.
>
> **STATUS: partially closed by the QH-01 work** — that increment adds exactly those
> real-call-path `dry_run` negatives and **mutation-verified** that deleting each of 9
> enforcement calls turns exactly one named test red. Two `repo_dir` guards remain
> uncovered (no `dry_run`; reaching them needs SSH) — recorded, not hidden.
**Severity: high. Confidence: VERIFIED (reported by review, mechanism confirmed).**

A control with a green test suite is not a verified control. Observed on the
provisioning path: removing the `pool` validation call from
`execute_ops_vm_lab_provision_guest` leaves every new test passing, because the
tests invoke the validators directly rather than through the call path. Worse,
one test's bad-input list mirrors the implementation's reject-list, so it can
only ever confirm what the code already rejects — it cannot detect an
**under-inclusive** rule, and it did not: both live findings passed it.

The good pattern already exists in the same file — the image negative test fails
on revert and derives its cases from attack classes (quote breakout,
metacharacters, a homoglyph, leading `-`/`.`, over-length).

Proposed fix / convention:
- For each security control, at least one test that exercises the **real call
  path** and goes red if the enforcement call is deleted.
- Derive negative cases from attack classes, never from the implementation's own
  reject-list.
- Consider a small harness that removes each named enforcement call in turn and
  asserts the suite fails (targeted mutation testing over a curated list).

Acceptance: for every control listed in the security-controls catalogue, deleting
its enforcement call turns at least one named test red.

### QH-03 — Host scripts continue after a failed step (fail-open shape)

> **[REVIEW 2026-07-25] REFUTED FOR THE SCRIPT IT NAMES; the real fail-open scripts are
> two others.** Verified on `main` @ `f9388393`:
> - The `-e` observation is right and **generalises: 10 of 10** bash-body host-script
>   consts in `vm_lab/mod.rs` use `set -uo pipefail` without `-e`.
> - **But "any mid-script failure can be reported as success" is false for the
>   provisioning script**, which guards every consequential step with **7 explicit
>   `exit N`** (`:6575-6620`). And `run_guest_script` checks `status.success()`
>   (`mod.rs:4585`), so the contract is **conjunctive: exit 0 AND sentinel** — stronger
>   than this item assumes. Adding `-e` there is close to a no-op.
> - The supporting evidence doesn't support the claim either: "an injected command ran and
>   the script still exited 0" is an *injection* artifact — the injected command runs and
>   the rest of the script then legitimately succeeds. **Identical under `set -e`.**
> - **The genuinely fail-open scripts are `HOST_RECOVER_VMS_SCRIPT` (`:5087`) and
>   `HOST_DISK_STATUS_SCRIPT` (`:5212`)** — zero non-zero exits, every probe `|| true` /
>   `|| echo`, and a terminal sentinel (`RECOVER-END` / `DISK-END`) printed
>   **unconditionally**. A wholly failed run there reports success.
> - **The acceptance criterion is satisfiable without the thing being true:** "a test
>   asserts this for at least the provisioning and launch paths" targets the two scripts
>   that *already* exit non-zero on every failure path. Retarget at recover-vms and
>   disk-status, and assert the conjunctive contract.
> - "Audit every `const *_SCRIPT`" is the wrong predicate — it misses
>   `recover_guest_network.rs:260/280/296` and sweeps in 6 shell-free path consts.
>
> Severity should be split: VERIFIED that `-e` is absent in all 10; REFUTED that this
> makes the provisioning script fail-open.
**Severity: high. Confidence: VERIFIED for the provisioning script; other scripts UNAUDITED.**

The provision-guest script uses `set -uo pipefail` **without `-e`**. During the
QH-01 demonstration an injected command ran and the script still exited `0`, so
provisioning reported success. This is independent of injection: any mid-script
failure can currently be reported as success.

This is arguably broader than QH-01 — it affects correctness of every host
operation, not only security.

Proposed fix: audit every `const *_SCRIPT` in `vm_lab/mod.rs` (and any other
remote script) for `-e` / explicit error handling, and make each step either
fail the script or be deliberately and visibly tolerated.

Acceptance: a failed step in any host script produces a non-zero exit and a
diagnosable message; a test asserts this for at least the provisioning and
launch paths.

### QH-04 — Assign an owner to the assignment/traversal atomicity exposure

> **[REVIEW 2026-07-25] Mechanism VERIFIED and genuinely PRODUCT + release-blocking — but
> "unrecoverable" is FALSE, and the citation trail is broken.**
> - **"Permanently restricts itself" overstates it.** On the next successful reconcile the
>   daemon clears `restriction_mode` **and** `reconcile_failures` — **even from
>   `Permanent`** (`daemon.rs:9067`/`:9069`) — `apply_dataplane_generation` explicitly
>   admits `FailClosed` as a recovery state (`phase10.rs:5045-5055`), the retry gate keeps
>   firing because `last_applied_assignment` only updates on success (`:9065`), and
>   `StateRefresh` IPC is exempt from the restricted gate (`:7635-7640`). Correct wording:
>   ***"stays restricted until the matching half arrives or an operator issues
>   `state refresh`."*** The exaggeration matters — it drives a heavier fix than needed.
>   *(This error also propagated into loop-journal notes #435/#436, corrected in #444.)*
>   The real cost is operational: for the whole window the tunnel is down and every
>   mutating IPC (`route advertise`, `exit set`) is refused, so dependent steps hard-fail.
> - **Tolerance is ~5 seconds** — `DEFAULT_MAX_RECONCILE_FAILURES = 5` (`daemon.rs:338`)
>   × `DEFAULT_RECONCILE_INTERVAL_MS = 1_000` (`:337`).
> - **A second equality site this item omits:** `sync_traversal_runtime_state`
>   (`daemon.rs:6208-6218` unmanaged, `:6224-6230` missing). Any fix must cover both.
> - **The citation trail is wrong.** `NodeEngineFlipDispositions_2026-07-24.md` (D1)
>   contains **none** of the claimed detail, scoping, arithmetic, or fix shapes, and
>   `TraversalSelfSustenancePlan` does not cross-reference this exposure (it cites the same
>   function for the *120 s freshness* mechanism — a different trigger). The real source is
>   an **uncommitted** comment, `live_linux_two_hop_test.rs:335`, whose own citation is
>   wrong. A textbook QH-06 instance inside the QH-06 register.
> - **Product, not just lab — confirmed, with a trigger this item misses.** Beyond the
>   orchestrator's separate stages: `ops assignment-refresh` (the shipped systemd path)
>   installs the **traversal** bundle unconditionally but short-circuits the **assignment**
>   re-mint whenever the current one has more than `MIN_REMAINING_SECS` (default 180 s)
>   left (`main.rs:9510`, `:9520-9528`). So the invariant is "traversal always, assignment
>   only near expiry" — *content* equality, not *timing*. Change `NODES_SPEC` and the next
>   timer tick (60 s ± 10 s) installs a new traversal index against the **old** peer set:
>   a **tens-of-seconds-to-~2-minute** window against a 5-second tolerance, per node, no
>   orchestrator involved. Plus the daemon's remote-pull path uses **independent**
>   `traversal_url`/`assignment_url` with independent watermarks and no cross-binding
>   (`daemon.rs:434-435`), where a partial refresh is a silent `Skipped`. **And a third
>   input the item omits: membership revocation** — `build_verified_traversal_index`
>   errors if a bundle's node is not `Active` (`:6837-6843`), so a revoke landing before
>   the matching re-mint trips the same equality failure. Any fix scoped to
>   "assignment + traversal" alone is under-scoped.
> - **Recommended shape: evaluate set-equality against a staged pair** — it changes *when*
>   the existing check fires, not *what* it enforces, so fail-closed is preserved, and both
>   sites already hold the peer set and the index. Scope the grace strictly to the
>   transitional case (peer present in one half only) and keep it hard-failed for a peer
>   missing from both, or stale/replayed. Co-distribution alone cannot fix the remote-pull
>   path; the single combined artifact is the durable fix but is a signed wire-format change.
> - **Acceptance criterion is satisfiable without the thing being true** (unquantified
>   "a peer-set change"; "live-proven" against the lab proves only the lab path; it never
>   says the daemon must not fail closed). Rewrite per QH-07 to name artifact and field.
**Severity: high (product, not tooling). Confidence: VERIFIED analysis, UNASSIGNED work.**

A node's managed peer set and its signed traversal state must agree exactly; the
daemon fails closed — correctly — when they do not. Nothing structurally enforces
that the two halves are distributed together. Any flow that **changes** a peer
set and installs the halves as separate steps opens a window in which the node
permanently restricts itself and tears down its tunnel.

Detail, the affected-node scoping, and the reconcile-interval arithmetic behind
the short window are recorded in `NodeEngineFlipDispositions_2026-07-24.md` (D1)
and cross-referenced from `TraversalSelfSustenancePlan_2026-07-23.md`. The lab
orchestrator itself distributes the two halves as separate stages.

This is the highest-severity *product* finding of the session and currently has
no owner. Candidate shapes recorded in D1: co-distribute atomically, a single
combined artifact, or evaluate set-equality against a staged pair.

Acceptance: an owner, a chosen shape, and a live-proven test that a peer-set
change cannot open the window.

---

## P2 — Cheap and high leverage

### QH-05 — A comment claiming a security property must name the test that proves it
**Severity: medium. Confidence: VERIFIED.**

A doc comment asserting "the caller forbids a literal single quote, so the
quoting cannot be escaped" was false, and it is a substantial part of why the
defect survived — readers trusted it. The **corrected** comment was then also
false: it enumerated the single-quoted, validated values and silently omitted the
one value that carries quotes by construction, which is precisely the gap QH-01
exploits.

Proposed convention: a comment that asserts a safety invariant must name the
enforcement point *and* the test that proves it ("enforced by X, verified by
test Y"). A safety claim with no test name is a hypothesis and should read as
one.

### QH-06 — Put a verification date and a recheck command on "known broken" claims
**Severity: medium (process). Confidence: VERIFIED.**

Two "pre-existing red gates" were repeated as guidance to three separate work
lines this session and neither reproduced:
- Full-workspace `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  passes with **no exclusions** on the pinned toolchain reached via the
  `$HOME/.rustup/toolchains/1.88.0-*/bin` PATH prepend; `-p rustynet-mcp` alone is
  clean. The red was a Homebrew-1.97 artifact, not a code defect.
  ★ **But the trap survives, so state the fix as a positive instruction, not as
  "the red is fake."** Confirmed independently by two lines: the toolchain reports
  `clippy 0.1.88` **only** once that PATH prepend is in place. Without it, Homebrew's
  `cargo` shadows the pinned one and the red **returns** — and a correct
  `rust-toolchain.toml` alone does NOT prevent the shadowing. So anyone who reads
  "the exclusion is unnecessary", runs the gate without the prepend, and sees the red
  will reasonably conclude the withdrawal was wrong and re-add `--exclude
  rustynet-mcp`. The guidance must therefore be: *prepend the pinned toolchain's bin
  directory, then run unexcluded* — and if `rustynet-mcp` still goes red under a
  confirmed `clippy 0.1.88`, treat it as a real finding rather than the known artifact.
  This is how the stale belief regenerates if the mechanism isn't recorded alongside
  the correction.
- `scripts/ci/check_backend_boundary_leakage.sh` passes.

Also stale and corrected during the session: an assertion that CI's clippy could
not be reproduced locally (it can, via the PATH prepend), and a claim that a
frozen archive's passing rows demonstrated a capability the current engine lacks
(those rows predate the assertion that would have tested it).

A further instance, found later the same session: the offline-build / SOCKS
cache-seed procedure recorded for Fedora provisioning was unnecessary for the
libvirt guest `fedora-x86-1`, which has **direct internet egress**. Note the
scope carefully — that finding is about the x86 box's guest and does **not**
establish the same for the Mac UTM guests, where the offline procedure may still
be required. Correcting a stale belief too broadly is its own failure mode.

Stale beliefs cost more agent effort this session than any single bug.

Proposed fix: any claim that gates behaviour ("always exclude X", "Y is known
red", "Z cannot be reproduced") carries a verified-on date and a one-line
recheck. Re-verify before inheriting.

### QH-07 — A ledger column reports `pass` for a stage that has never passed
**Severity: HIGH — corrected 2026-07-25, was "medium". Confidence: VERIFIED (quote-aware parse, reproduced independently twice; alias table and lifetime records read directly).**

> **[REVIEW 2026-07-25] THE RETRACTION BELOW IS FALSE — reclassify this item to
> SEVERITY HIGH and act on it FIRST.** The retracted "43 false-green `pass` rows" claim
> was **CORRECT**. Verified by hand with a quote-aware parser (`csv.reader`, column
> located by header **name**, index 46, 108 data rows):
> **`pass: 43`, `skip: 22`, `fail: 34`, `not_run: 9`.**
> The 97/9/1 figures below are reproducible **only by a naive comma split** —
> `awk -F, '{print $47}'` yields `98 skip / 9 not_run / 1 fail` — because every row
> carries a quoted `notes` field (index 16) containing commas, which shifts the whole
> stage block. The retraction was written from a shifted parse.
>
> **The false-green is real and it is a LEDGER-CODE defect, not a prose defect.**
> `live_two_hop_validation` lifetime record: **116 fail / 263 skip / 0 pass — it has
> never passed.** `traffic_test_matrix`: 260 pass. The alias table collapses **both**
> into one column — `live_lab_run_matrix.rs:3744` `"traffic_test_matrix" => Some("two_hop")`
> alongside `:3770` `"live_two_hop_validation" => Some("two_hop")` and `:3747`. So
> `linux_stage_two_hop = pass` means *"the mesh pinged"* while the chained-exit proof was
> skipped. This item's own diagnosis — *"the weakness is in how criteria are written, not
> in the ledger code"* — is therefore **wrong**: the NO-VERDICT logic correctly handles
> *absence*, but here the cell says `pass`.
>
> **Why this is the most urgent item in the register:** `CLAUDE.md:418` / `AGENTS.md:418`
> instruct **every agent** to "verify the appended row in `live_lab_node_run_matrix.csv`"
> as their acceptance criterion — pointing them at that column.
> **Fix:** (a) strike the retraction and restore the finding with the cross-ledger proof;
> (b) split `traffic_test_matrix` out of the `two_hop` column, or fail the append when two
> distinct stages map to one column. Note the repo already fixed the identical bash-era
> "52 passes" false-green (`live_lab_run_matrix.rs:430-433`) by splitting the *ledgers*,
> and left the *stage aliasing* in place.

**The retraction that used to sit here was false, and it was mine. It is struck.**
The original claim — that the `two_hop` column carries false-green `pass` rows — is
CORRECT. Confirmed with a quote-aware parse (`csv.reader`, column located by header
name):

```
linux_stage_two_hop   pass 43 | skip 22 | fail 34 | not_run 9      (108 data rows)
```

The retracted figures (97 skip / 9 not_run / 1 fail, "no pass rows") are reproducible
**only** by a naive comma split — `awk -F, '{print $47}'`. **All 108 rows contain a comma
inside a quoted field**, so that split shifts every row and reads the wrong column
entirely. The retraction was written from a shifted parse and then propagated into a
disposition ledger before it was caught.

**The root cause is a ledger-code defect, not a wording problem.** Three stage names
alias onto the same column in `crates/rustynet-cli/src/live_lab_run_matrix.rs`:
`"traffic_test_matrix" => Some("two_hop")` (`:3744`), `"live_two_hop" => Some("two_hop")`
(`:3747`), `"live_two_hop_validation" => Some("two_hop")` (`:3770`). Lifetime records:

```
live_two_hop_validation   skip 263 | fail 116 | pass 0     ← has NEVER passed
traffic_test_matrix       pass 260 | skip 75 | not_proven 34 | fail 10
```

So `linux_stage_two_hop = pass` means *"the mesh pinged"*, while the chained-exit proof it
appears to attest was skipped or failed. The `NO-VERDICT` guard is not a mitigation here:
it correctly refuses to read **absence** as success, but this cell affirmatively says
`pass`.

**Why this outranks the rest of the register:** `CLAUDE.md` / `AGENTS.md` (~line 418)
instruct *every* agent to verify the appended row in `live_lab_node_run_matrix.csv` as
their acceptance criterion — pointing them at this column.

Fix — ★ **the obvious structural guard is WRONG, corrected 2026-07-26:**

"Fail the append when two distinct stage ids map to one column" **cannot be used**: aliasing is
pervasive and mostly *legitimate*. Measured on the live table — `two_hop` 3 ids, `managed_dns` 3,
`reboot_recovery` 3, `bootstrap` **4** (`prime_remote_access`, `cleanup_hosts`, `bootstrap_hosts`,
`collect_pubkeys`), plus `network_flap`, `lan_toggle`, `mixed_topology`, `role_switch_matrix` and
`secrets_not_in_logs` at 2 each. Most are **synonyms** — the same logical stage under different
naming eras or engines (`live_two_hop` → `live_two_hop_validation`) — and those *must* keep
collapsing. This bug is different in kind: `traffic_test_matrix` measures a genuinely different
thing from `live_two_hop_validation`. A purely structural check cannot tell a synonym from a
category error without **declared intent**.

Corrected plan, in this order:
- **(a) NOW, minimal, no schema change: drop the `traffic_test_matrix → two_hop` alias.** The
  column then reflects only real two-hop stages, and `traffic_test_matrix` reports into no
  roll-up column until one is added deliberately. One line; kills the false-green immediately;
  no data loss, since per-stage results still live in `live_lab_node_stage_results.csv`.
- **(b) Separately: an explicit synonym table.** Declare which ids are deliberate aliases, then
  fail the append on any collision *not* declared. This is the real guard, and it is a design
  task rather than a one-liner.
- **(c) Last, if wanted: split into its own column** — a genuine **schema migration**. Stage
  columns are a fixed header list (`linux_stage_*`/`macos_stage_*`/`windows_stage_*`, 39
  references); a split adds three columns and changes the schema for both
  `live_lab_node_run_matrix.csv` (108 rows) and the frozen bash archive (549 rows), so every
  existing row predates the new header and any reader keyed on column position or count is in
  scope. Needs its own review.

★ **The fix is FORWARD-ONLY — say so wherever the column is read.** Dropping the alias stops new
contamination; it does not rewrite the 43 existing `pass` rows, which remain
`traffic_test_matrix` results sitting in the `two_hop` column. So historical rows stay misleading
after the fix, and anyone reading them needs either the caveat now carried in `CLAUDE.md`/
`AGENTS.md` (~line 418) or a schema/version marker distinguishing pre- from post-fix rows.

The repo already knows this class — `live_lab_run_matrix.rs:430-433` documents the bash-era
"52 passes" false-green and fixed it by splitting *ledgers*, leaving the *stage aliasing* in
place, which is how it reproduced inside the `--node` ledger.
- (b) Keep the original point too: acceptance criteria should name the artifact and the
  field within it (a stage report's `status` plus its data block), never "the ledger says
  pass". That is now necessary rather than merely tidy.

**Process note, recorded because it is the instructive part.** This item's false retraction
was authored by the coordinator, using an unsafe parser, while explicitly invoking this
register's own norm to overturn a correct finding — and it was then written into a
disposition ledger on that authority. Two transferable rules: **never parse these CSVs
with a naive `awk -F,`** (every row has quoted comma-bearing fields), and **authority is
not evidence** — a coordinator's verification needs the same scrutiny as a worker's, and in
this case got less.

### QH-08 — Runs should execute from a worktree nobody edits
**Severity: medium (process). Confidence: VERIFIED near-miss.**

Both physical labs are driven from the same working tree that people commit in.
During this session one line rebased and committed in that tree while another
line's run was sourcing from it. No evidence was corrupted — the failure being
investigated was decided before the mutation, which was provable from timestamps
— but that was luck, not design.

The precise constraint is narrower than the folklore: **no tracked edits in the
tree a run executes from**. Edits inside a gitignored worktree are invisible to
the run's dirty check, and the hard failure mode is a setup-manifest hash
mismatch on the orchestrator source specifically.

Proposed fix: runs execute from a dedicated worktree that is never edited or
committed in, removing the class rather than relying on everyone remembering.

---

## P3 — Quality of life

### QH-09 — Audit other evidence-truncation sites
**Severity: medium. Confidence: VERIFIED for the stage log; other sites UNAUDITED.**
**Status: a fix for the stage-log site is already assigned (sidecar spill).**

★ **THIS ITEM WAS SUBSTANTIALLY WRONG AND IS CORRECTED BELOW. The wrong version is
kept visible because it is the alarming one and would otherwise be re-derived.**

**What it claimed:** a stage log was truncated to its last ~4 KB of ~14 KB, keeping
the tail, so the earliest and most diagnostic material was destroyed every time —
"structural, not bad luck", and it "will have quietly degraded earlier
investigations". A sidecar-spill fix was assigned.

**What is actually true** — established independently twice, by the register's
adversarial review and then by the line that had been relying on the claim:
- **No evidence is destroyed.** The test binary is invoked with `--log-path` and
  writes its **own complete log** to the report directory (measured: 13,583 bytes,
  containing every section *and* the per-node status blocks). Only the stage
  record's **inline copy** is clipped, to `STAGE_FAILURE_STREAM_BUDGET = 4000`
  (`vm_lab/orchestrator/stage/mod.rs:307`).
- **The tail-keeping is deliberate and correct for its intended case**, and is
  documented as such in the code (`:339-345`): a failing CLI dumps ~11.5 KB of
  usage text and prints the real error **last**, so keeping the tail is what makes
  that case diagnosable. Changing it would break the case it was built for.
- **The sidecar-spill fix is therefore largely redundant** — the sidecar already
  exists. It was assigned on a false premise (mine).

**The real defect is much smaller, and it is a false signal rather than data loss.**
The disclosure line announces that output was clipped **without naming the complete
artifact sitting beside it in the same report directory**. So a reader is told
evidence was lost when it was not — which is worse than unhelpful, and it produced
**two** wrong conclusions in one day: this register item, and a coordinator warning
to a worker that its probe data had been eaten (it hadn't; the worker had simply
read the stage record instead of the log file).

Fix: have the disclosure name the full artifact. Note the shape constraint — the
caller holds `log_path_str` while the pure formatter does not, so it belongs at the
call site or as an optional parameter, across roughly eight call sites. Keep it
minimal; do **not** change the truncation behaviour itself.

Genuine remaining work: audit whether any *other* diagnostic output is truncated,
sampled or summarised **without** a complete copy written elsewhere. That is the
question this item should have asked. The lesson for the register: "the evidence was
destroyed" and "I read the wrong file" look identical from the outside, and only one
of them is a defect.

### QH-10 — Reachability probes must use the protocol the task needs
**Severity: low. Confidence: VERIFIED.**

The Windows lab guest does not answer ICMP (Windows Defender blocks inbound echo
by default). A healthy guest was very nearly recorded as down on the basis of a
failed ping; `virsh` domain state plus a TCP/22 probe showed it running with SSH
open. A separate, long-standing false negative exists in the other direction on
macOS, where an in-process TCP probe reports the port closed for every node.

Proposed fix: readiness and reachability checks assert the protocol actually
required (a TCP connect, or a real SSH session), never ICMP; and any probe that
is known to produce false negatives in a given environment says so at the point
of use.

### QH-11 — Durable working state must not live in the temp directory
**Severity: low. Confidence: VERIFIED.**

A scratch directory under `/private/tmp` was cleaned mid-session, removing a
coordination status file and a git worktree that a work line was using as its
commit path (the worktree had to be pruned and recreated). Anything expected to
survive a session belongs in the repo, or in a stable per-project location.

### QH-12 — Finish deduplicating the single-quote validation rule

> **[REVIEW 2026-07-25] REFUTED AS WRITTEN — every number is wrong; written against a
> different tree.** Verified on `main` @ `f9388393`:
> - **`ensure_single_quoted_script_value` does not exist anywhere in `crates/`** (0 hits).
>   The pre-existing composed helper is **`ensure_orchestrator_arg_safe`** (`mod.rs:5067`).
>   *(QH-01's third bullet also cites the nonexistent name — same error.)*
> - **One** caller, not two (`mod.rs:5834`); all other references are tests.
> - **Nine** hand-rolled `contains('\'')` sites, not eight: `:5262, 5541, 5545, 5719,
>   5826, 5830, 5851, 5865, 6511`. (The 10th match is the helper's own body at `:5069`.)
> - **The framing points at the weaker answer.** The file has **four** idioms, and one of
>   them is **`shell_quote` (`mod.rs:37993`) — a correct POSIX `'\''` escaper already used
>   at ~20 sites.** Deduplicating toward the hand-rolled *reject* rule, as this item
>   implies, would consolidate on the weaker of two available primitives. Escaping
>   subsumes rejection; that is why QH-01's fix was redesigned around it.
>
> **STATUS: CLOSED by the QH-01 work** (see `QH01TemplateInjectionFixPlan_2026-07-25.md`).
> The existing helper was *extended* into the canonical one (with an explicit
> `AllowEmpty`) rather than adding a fifth idiom, and all nine sites now point at it.
**Severity: low, but it is QH-01's precondition. Confidence: VERIFIED (8 sites counted).**

A shared helper composing the metacharacter check with the single-quote rejection
now exists, and two sites use it — but **8** hand-rolled copies of the same rule
remain in `vm_lab/mod.rs`, one of them a few lines above the render chain that
QH-01 exploits. Partial deduplication is the worst state: a reader cannot tell
which copy is canonical, and that ambiguity is what allowed the original defect
to persist. Finish it, so §3's one-hardened-path claim is actually true.

### QH-13 — Validate values for the sink they actually reach

> **[REVIEW 2026-07-25] UPGRADE: confidence INFERRED → VERIFIED; severity medium → HIGH.
> This is the second-most-urgent item in the register.** No SSH needed to confirm it:
> - **The mechanism is vendor-documented.** `ssh(1)` on this machine: *"If supplied, the
>   arguments will be appended to the command, separated by spaces, before it is sent to
>   the server to be executed."* Client argv does **not** survive as remote argv; the
>   remote login shell re-parses. Documentation of the sink's own behaviour is stronger
>   evidence than one observed execution, so **reproduction is not required** — the
>   register's "confirm with a non-destructive marker before writing the fix" can be
>   relaxed. The residual is a *host-configuration* assumption (that the remote shell
>   interprets metacharacters), not a code uncertainty — and the code must be safe
>   regardless.
> - `run_host_cmd` (`mod.rs:6628-6677`) does `command.arg("--").arg(endpoint);` then
>   appends every element of `args`. Its doc comment claimed **"argv-only (§4)"** — false,
>   and that claim appears at **9 sites** with **zero** enforcement anywhere (QH-05
>   violated at exactly the site QH-13 is about).
> - **This item's own premise understates the exposure.** It says a pool value *"validated
>   for a single-quoted-script context"* also reaches SSH. On `main`, `pool` was
>   **not validated at all** on the provision path, so it reached **two** unguarded sinks:
>   the SSH argv (`findmnt --target <pool>`, `:6459`) **and** `POOL='__POOL__'` — a direct
>   quote breakout with no placeholder trick. The premise holds only for
>   `host_disk_status`.
> - **Reachable on the real lab host:** the `findmnt`/`lsblk` branch is gated on
>   `host.pool_disk_model`, which `ubuntu-kvm-1` declares (`vm_lab_inventory.json:21`).
> - **Worse in kind:** `:6472-6477` passes `device`, derived from the *previous command's
>   remote stdout* — remote output flowing into remote argv, then a remote shell.
>
> **Partially mitigated by QH-01:** `pool` now has an allowlist validator placed above
> **both** sinks, so its script half and its SSH half are closed **for
> `execute_ops_vm_lab_provision_guest` only**. **Still open:** `run_host_cmd` itself, the
> other seven call sites (incl. `repo_dir`, which *is* validated for the script sink and
> not for this one), and the stdout-derived `device`.
> **Structural fix:** `run_host_cmd` is a **single chokepoint** — validate inside it rather
> than at eight call sites, and either correct or make true the `argv-only` comment.
> Acceptance must be **per-sink**: for every value crossing into
> `run_host_cmd`/`run_host_git`, a named validator call at the call site plus a test that
> goes red when that call is deleted.
**Severity: medium. Confidence: INFERRED — mechanism is standard, not reproduced here.**

A pool value validated for a single-quoted-script context is also passed to a
command executed over SSH. OpenSSH joins post-host argv with spaces and the
remote sshd executes the result through a login shell, so client-side argv does
not survive as remote argv — meaning shell metacharacters permitted by the
single-quote validator (`;`, `|`, `&`, redirections, globs) would reach a remote
shell. The relevant doc comment claims "argv-only", which is what makes the sink
look safe.

This is the one finding in this document that was **not** demonstrated by
execution — the reviewer had no key-auth sshd available. The mechanism is
well-established OpenSSH behaviour, so treat it as real, but confirm with a
non-destructive marker before writing the fix, and do not run injection tests
against a shared lab host that another line is using.

### QH-14 — `ops vm-lab-provision-toolchain` is Debian/apt-only despite detecting other distros
**Severity: medium (tooling completeness). Confidence: VERIFIED live.**

`GUEST_TOOLCHAIN_SCRIPT` in `crates/rustynet-cli/src/vm_lab/mod.rs` detects Fedora
correctly and then unconditionally invokes `apt-get`. There are **zero** `dnf`
occurrences anywhere under `crates/rustynet-cli/src/vm_lab/`. Provisioning a
Fedora guest therefore fails with `timeout: failed to run command 'apt-get': No
such file or directory` — after the detection has already established that the
guest is not Debian-family.

The immediate need was met out-of-band with a `dnf` equivalent satisfying the
script's own verify contract (the guest now reports `ALL PREREQUISITES
SATISFIED`), so this is a tooling gap rather than a blocked lab.

Proposed fix: branch on the detected family and implement the `dnf` path, or fail
loudly and specifically ("Fedora detected but only apt provisioning is
implemented") instead of running a package manager that cannot exist. The current
shape is the worst case — it detects the condition and then ignores it.

Acceptance: provisioning a Fedora guest either succeeds or fails with a message
naming the unimplemented path; a test covers the non-Debian branch.

### QH-15 — The Windows build budget is unoverridable and single-threaded
**Severity: medium. Confidence: VERIFIED by code read.**

On the `--node` Windows path (`orchestrator/adapter/windows_install.rs`) the build
timeout is a hard-coded `BUILD_TIMEOUT = 3600s` with no flag to override it, and
the bootstrap forces `CARGO_BUILD_JOBS=1` when the variable is unset. On a 2-vCPU
guest that combination means a slow first build can consume the entire budget and
fail the stage **for a reason unrelated to what the stage is testing** — which is
the same class of problem as QH-09: infrastructure noise presenting as a product
result.

Related trap worth recording next to it: `CARGO_TARGET_DIR` must NOT be
redirected, because install hardcodes `<workdir>\target\release\`. And on this
path `target/` is *not* deleted between runs (the wipe belongs to the legacy bash
path), so warming the build cache genuinely helps.

Proposed fix: make the timeout configurable, default the job count to the guest's
CPU count, or both. At minimum, distinguish "build exceeded its budget" from
"build failed" in the stage outcome so a timeout is never read as a product
defect.

### QH-16 — A gate run through a pipeline reports the PIPE's exit status, not the tool's
**Severity: HIGH (falsifies evidence). Confidence: VERIFIED — it invalidated a real green result in this session.**

`cargo test --workspace --all-targets --all-features | tail -60` exits with **`tail`'s**
status, which is essentially always `0`. A worker reported a green workspace test gate on
that basis; the truncated tail also under-reported the test count by two orders of
magnitude (27 vs ~10,000). The worker caught and retracted it unprompted, but nothing in
the tooling or the conventions would have caught it.

This ranks above most defects on this list because it does not produce a wrong *program* —
it produces a wrong *belief about whether the program was checked*, which is the failure
mode every other item here is downstream of. Any agent piping a gate for readability is
silently reporting the pipe.

Proposed fix:
- Convention: gate commands are run **unpiped**, redirecting to a file and reading the
  tool's own exit code; or `set -o pipefail` / an explicit `${PIPESTATUS[0]}` check.
- Where a wrapper runs gates on an agent's behalf, have it capture and surface the tool's
  status itself so the caller cannot get this wrong.
- Treat any reported gate result whose evidence is a truncated tail as unverified.

Acceptance: a gate result is only accepted with the tool's own exit code, captured without
a pipeline in the path.

**Related, same family (see QH-07):** `awk -F,` on the lab CSVs silently reads the wrong
column, because every row carries quoted comma-bearing fields. That one produced a
confidently wrong "no `pass` rows" conclusion which was then used to overturn a correct
finding. Both are cases of a convenience idiom quietly invalidating evidence rather than
failing loudly.

### QH-17 — The Windows lab-image provisioning path is internally inconsistent
**Severity: medium. Confidence: VERIFIED by code read on `main`.**

Two independent defects in the same area, found while standing up MSVC Build Tools on
`windows-x86-1`:

1. **`-SkipRustup` does not skip everything it implies.**
   `scripts/bootstrap/windows/Provision-RustyNetWindowsLabImage.ps1` (~`:183-184`)
   unconditionally sets a **machine-scoped** `CARGO_HOME=C:\CargoHome` and prepends its bin
   directory to the machine PATH — **outside** the `-SkipRustup` guard. So invoking the
   script with that flag on a guest that already has a working toolchain silently redirects
   cargo away from the existing `~/.rustup` toolchain and away from any warmed registry
   cache. A flag whose name promises not to touch the toolchain does exactly that.
   The immediate work avoided it by replicating only the Build Tools step, but the next
   person to trust the flag will not.

2. **Two repo paths install different Windows SDKs.**
   - `scripts/bootstrap/windows/RustyNetBuildTools.vsconfig` — used by `Ensure-BuildTools`,
     i.e. the path a live run takes: VCTools + **Windows11SDK.26100** + VC.CMake.Project.
   - the provisioning script's `--add` list: VCTools + VC.Tools.x86.x64 +
     **Windows11SDK.22621**.
   A hand-provisioned guest therefore diverges from what the run's own code would install.
   Divergence between "the canonical image" and "what the run installs" is the drift class
   that produces failures nobody can reproduce.

Proposed fix: move the `CARGO_HOME`/PATH mutation inside the `-SkipRustup` guard (or rename
the flag to describe what it actually skips), and make both paths consume the single
`vsconfig` so the component set has one definition.

Acceptance: `-SkipRustup` provably leaves cargo/rustup environment untouched, and grepping
for an SDK component id yields exactly one authoritative definition.

**Related (see QH-15):** the same investigation found the forced `CARGO_BUILD_JOBS=1`
entered the tree incidentally in `4e6feb0e`, a large daemon/IPC change whose message says
nothing about parallelism — so it is a soft default with no recorded rationale, not a known
stability guard, and serialising a release build on a 2-vCPU guest is the main risk to the
unoverridable 3600 s budget.

### QH-18 — The live-lab singleton gate is a `pgrep -f` pattern match that can match its own launcher
**Severity: HIGH — both directions now VERIFIED. There is no per-host run exclusion at all for the documented invocation form.**
**Verified against `main` @ `b7667cce`, on `ubuntu-kvm-1`.**

The per-host "is a run already in flight?" gate matches on the orchestrator's command
string. Driving a launch **inline** over SSH — `ssh box '<script text>'` — places the literal
string `vm-lab-orchestrate-live-lab` into the remote `bash -c` argv, so the gate matches its
own command line and aborts with "a run is already in flight" when the host is idle.
Confirmed by `pgrep -af` showing only the launcher itself. `HOST_LAUNCH_SCRIPT` is immune
only incidentally: it executes from a file, so its argv is just `bash /path/script`.

Two consequences, and the second is the one that matters:
- **False positive (verified):** an operator or agent driving the orchestrator inline is told
  the host is busy when it is idle, and may go looking for a phantom run. Cost: wasted time
  and a wrong mental model of lab state.
- ★★ **False negative — CONFIRMED, and worse than "the pattern might miss a form":**
  1. **The gate is not in the orchestrator at all** — it exists only in `HOST_LAUNCH_SCRIPT`.
     A grep of the orchestrator for any concurrency or singleton check finds nothing. So
     `ops vm-lab-orchestrate-live-lab` — **the exact form the runbook documents**
     (`WindowsExitNodeRunbook_2026-06-04.md:61`) — has **no mutual exclusion whatsoever**.
     Two operators following the runbook on one host get two concurrent runs, silently.
  2. **No real lock exists anywhere in `vm_lab`.** The only lock-shaped thing is
     `network_prepare.rs:46 LEASE_LOCK_FILE ".acquire.lock"`, which guards network-lease
     acquisition and is unrelated to run exclusion.
  3. **The pidfiles cannot serve as one.** `HOST_LAUNCH_SCRIPT` does
     `rm -f state/host-lab-runs/*.pid` *after* the pgrep gate — they are stop-path run
     handles, deliberately retired at launch.
  4. **The pattern matches a subcommand string, not the binary**, so sibling orchestrating
     subcommands (`vm-lab-run-live-lab`, `vm-lab-iterate-live-lab`, `vm-lab-setup-live-lab`,
     `vm-lab-overnight`, `vm-lab-run-suite`) are invisible to it. Whether each of those drives
     the same guests is NOT yet verified — needs-check, not a finding.
  5. `cargo run` is **not** a false-negative vector: the observed argv of a live run was
     `target/debug/rustynet-cli ops vm-lab-orchestrate-live-lab …`, so the string is present
     either way.
  ⇒ The gate can be **self-tripped by the caller's own command line and bypassed by the
  documented invocation**. Two concurrent runs on one physical lab corrupt each other's
  evidence and contend for the same guests.
  ★ **Consequence for multi-agent work:** coordinator-side token discipline is currently the
  *only* thing preventing concurrent runs on a host. Anyone assuming the tool enforces a
  per-host singleton is assuming a guarantee that does not exist.
  ★ **Fix must be taken by the ORCHESTRATOR, not the launcher** — otherwise the documented
  direct form still bypasses it.

Proposed fix: replace the pattern match with a real mutual exclusion — a pidfile or lockfile
whose liveness is confirmed by checking the recorded pid's identity (this repo already has a
pid-recycling-safe guard for the *stop* path that argv-verifies before signalling; the same
approach applies here), or an flock on a per-host lock path. Whatever is chosen, it must not
be satisfiable or defeatable by the shape of the caller's command line.

Acceptance: launching inline over SSH does not self-trip the gate, **and** a second launch
is refused while a real run is in flight regardless of how either was invoked.

Related, same area: the run's report directory must be created **outside** the repo, because
the dirty check counts untracked paths under the tree. Note the dirty check is otherwise more
carefully built than QH-08 implies — `git_worktree_is_dirty` (`mod.rs:29591`) deliberately
excludes the six evidence ledgers the orchestrator itself appends to, with a comment
explaining that otherwise a clean run would flip itself to dirty on its own evidence write
and fail the provenance check on a non-code change.

### QH-19 — "Escape at interpolation" is not one rule; every sink context has its own
**Severity: high (it is the conceptual gap behind QH-01/QH-13). Confidence: VERIFIED — each row below was found the hard way this session.**

The lesson people will take from QH-01 is "make the renderer own the quoting." That is
necessary and **not sufficient**, because a correctly `shell_quote`d value is still unsafe if
the sink re-parses it, terminates its own quoting, or interprets it as something other than a
word. Five distinct contexts turned up in one session, each needing a different control:

| Sink context | The control that actually protects it | Why escaping alone fails |
|---|---|---|
| Single-quoted shell literal | reject `'` | a quote closes the literal |
| Double-quoted shell literal | reject `$`, backtick, `\` | expansion and substitution still occur |
| **Heredoc body** (`<<'EOF'`) | **reject newline** (and any line equal to the terminator) | a body that emits its own terminator closes the heredoc early and the remainder executes in the **outer** script — quoting the heredoc gives no protection at all |
| **Nested command string** (`script -qec "…"`, and anything handed to `$SHELL -c`) | quote for **two** levels — pass via an exported variable and single-quote the inner command so the outer shell expands nothing | the inner shell re-parses, so escaping done for the outer shell buys nothing |
| **SSH post-host argv** (`run_host_cmd`) | quote each word for the **remote login shell** | OpenSSH joins argv with spaces and the remote sshd re-parses it as a command string; client-side argv does not survive (see QH-13) |
| **Path composition** (`BASE="$POOL/$IMAGE"`) | **confinement** — reject `/`, `..`, bound the length | orthogonal to quoting: `../../etc/passwd` is a perfectly safe shell *word* and a traversal |

Two rules follow, and they are the transferable part:
1. **Escaping and validation are complementary layers, not competing answers.** An escaper
   makes a value a single word; a validator constrains *which* words are acceptable. Neither
   subsumes the other, and the path row is the proof.
2. **A renderer cannot be safe context-free.** It must know, per binding, which context the
   value lands in — which is what a typed binding enum buys over a string substitution, and
   why a scan-order fix alone was insufficient.

Acceptance: every interpolation site is classified by sink context, and its binding type or
validator matches that context — not merely "it is escaped".

### QH-20 — An environment-dependent unit test intermittently fails and always runs slowly
**Severity: low-medium. Confidence: VERIFIED (four independent ways).**

`execute_ops_vm_lab_discover_local_utm_skips_inventory_update_when_no_live_ip_observed`
probes a non-resolvable host (`alpha-host`), so its runtime and outcome depend on how the
environment handles an unresolvable name. Observed taking **60–106 s** and observed both
passing and failing on branches that do not touch it — the "1 fail" attributed to an
unrelated branch was this test, confirmed by patch inspection (zero occurrences in that
diff), by an isolated re-run, and by seeing it pass on a second unrelated branch.

Why it is worth fixing rather than tolerating: it makes every workspace test run slower, it
produces failures that get attributed to whichever change is in flight, and it trains people
to explain away a red suite. A unit test should not depend on name resolution — inject the
resolver or use a reserved-for-testing name with a bounded timeout.

### QH-21 — Windows failure-artifact collection throws, losing diagnostics and inventing a second failure
**Severity: medium-high (destroys evidence exactly when it is needed). Confidence: VERIFIED live.**

`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs:257-261` runs under
`Set-StrictMode -Version Latest` and does:

```powershell
$filesToArchive = if (Test-Path -LiteralPath $logsDir) {
    Get-ChildItem -Path $logsDir -Recurse -File | Where-Object { ... }
} else { @() };
if ($filesToArchive.Count -gt 0) { ... }
```

The `else` branch is array-safe; the **taken** branch is not. With zero matches the pipeline
yields `$null`, and under `Set-StrictMode -Version Latest` `.Count` on `$null` throws
`PropertyNotFoundStrict`. Fix: wrap the assignment in `@( ... )`.

Two compounding consequences, and the second is the subtle one:
- **Diagnostics are lost precisely on failure** — this is the collect-failure-artifacts path,
  so it only runs when something already went wrong.
- **A spurious second failure appears.** The pre-cleanup hook's error is folded into the
  always-run `cleanup` stage, so `cleanup` is recorded as `fail` while its own message reads
  `cleanup completed`. Every Windows failure therefore produces two failed stages, one of
  which is an artifact of the reporting path rather than of the system under test.

Acceptance: a Windows failure with an empty logs directory collects cleanly, and `cleanup`
is not marked failed when it completed.

★ **REPO-WIDE SWEEP RESULT (2026-07-26) — this is a REGRESSION against an established
convention, not a systemic gap. That reframing is the actionable part.**
Swept every StrictMode-embedding source and `.ps1` in the repo using the discriminator *"a
StrictMode script reading a property on a pipeline result that can be `$null`"*. An automated
pass flagged 16 candidates; **15 were false positives** on inspection — including both sites in
the signing script (`$existingCerts = @(Get-ChildItem …)`,
`$alreadyTrusted = @($rootStore.Certificates | …)`). `@( … )` at assignment is **already the
consistent convention in this codebase**.
Exactly **two** genuine exposed sites existed: the one fixed here, and
**`script_template.rs:1281`** — introduced by code that landed the same day, i.e. new code
regressing an existing discipline rather than an old gap nobody had noticed.
So the standing rule to record is *"new PowerShell must maintain the `@()` discipline"*, and the
discriminator is what makes it checkable in review. Note also why non-StrictMode scripts are
exempt: they use `SilentlyContinue`, so the same unwrapped shape is harmless there — a sweep
that ignores this flags mostly noise.
Nuance for whoever fixes `:1281`: `-and` short-circuits, so wrapping only the right-hand pipeline
suffices; the left operand `$dnsRules.Count` is already safe because `$dnsRules` is
array-initialised.

### QH-22 — `first_failed_stage` is ALPHABETICAL, not chronological, and its name says otherwise
**Severity: medium. Confidence: VERIFIED — resolved by code read; the computation is correct, the naming is the defect.**

Observed: both the ledger and the A2 evidence verifier report `first failed: cleanup`, while
`state/stages.tsv` shows `preflight` failing at 18:52:19 and `cleanup` at 18:52:23 — i.e.
`preflight` failed **four seconds earlier**.

**Resolved — there is no arithmetic bug.** The verifier
(`live_lab_evidence_verifier.rs:529-532`) selects the first `Fail` while iterating `merged`,
which is a `BTreeMap<String, MergedOutcome>` (`:428`) and therefore iterates in **key-sorted
order**. So "first failed" means *alphabetically first*, and `cleanup` sorts before
`preflight`. The verifier's own comment states it mirrors "the same order the ledger writer
reports after its dedupe."

★ **The nuance worth keeping — what this says about the verifier's independence.** A2's
independence is **structurally intact in general**: it has its own implementation and does not
call the ledger's helper (`live_lab_run_matrix.rs:2122`). But on *this* property it
deliberately reproduces the ledger's ordering, so **its agreement is guaranteed by
construction and carries no evidential weight.** Generalising: a verifier that recomputes
values independently can still provide zero corroboration for a *derived ordering* it was
designed to mirror. Agreement is only evidence where the two paths could have disagreed.

**The defect is the name, and it caused real misdirection on first use.**
`first_failed_stage` reads as chronological. Here it pointed at `cleanup` — a downstream
artifact-collector bug (QH-21) — while the actual root cause was `preflight`, a one-hour guest
clock skew four seconds earlier. Triage driven off that field starts at the wrong stage.

Proposed fix: rename to reflect the ordering it actually uses, **or** emit a genuinely
chronological `first_failed_stage` (and keep the sorted one under an honest name if the merge
order is load-bearing elsewhere).

### QH-23 — An arm64-first assumption in the Windows installers, and the untestable-branch shape that hid a bug next to it
**Severity: high (blocked Windows bootstrap outright). Confidence: VERIFIED live on an x86-64 Windows guest, then fixed.**
**This is the cross-platform parity mandate's own thesis, demonstrated.**

`Install-RustyNetWindowsService.ps1:899-905` and `Install-RustyNetWindowsRelayService.ps1:150-155`
each hardcoded a signtool candidate list with **`arm64` first**, breaking on first match. The
Windows SDK installs `bin\<ver>\{arm64,x64,x86}` **side by side regardless of host
architecture**, so on an x86-64 guest the arm64 pattern matched and won — and x64 Windows
cannot execute an arm64 image (the emulation only runs the other way). Signing therefore
failed, the script called `Write-Error`, and `bootstrap_hosts` died before `active_exit` could
run.

★ **Why this matters beyond the fix:** that ordering was *correct* for the Apple-Silicon UTM
guest, which was the only Windows node the lab had ever had. The defect was invisible until a
real x86-64 Windows guest existed, and it would have blocked the Windows exit **and** relay
roles identically. This is precisely the class of latent single-architecture assumption the
`CrossPlatformRoleParityPlan` mandate exists to surface, and the box's first serious job found
one. Two sites, so record it as a pattern rather than a one-off.

Diagnostic note worth keeping, because it misled the coordinator: the failure *looked* like a
PowerShell quoting/parse error — `At line:1 char:108` with a caret under an `&` invocation. It
was not. A parse failure surfaces as `ParserError`/`ParseException`; this was a
**`WriteErrorException`**, i.e. the invoked script raising a terminating error under
`$ErrorActionPreference='Stop'`, with the caret pointing at the *invocation site* rather than
at broken syntax. The two are visually near-identical in a stage record.

Fix shape adopted: derive candidate order from the host architecture and list **only runnable**
arches (ARM64 → arm64,x64,x86; AMD64 → x64,x86; x86 → x86), consulting
`PROCESSOR_ARCHITEW6432` before `PROCESSOR_ARCHITECTURE` so a 32-bit process on a 64-bit OS
reports the native arch. Non-runnable arches are omitted deliberately: retaining one as a
"last resort" would trade a clear *SDK-not-installed* error for an obscure exec failure.

**Second, methodological finding from the same fix — the untestable branch.** The QH-21
`.Count` defect sat in a branch that **no test could reach as written**; the real work of fixing
it was *extracting* `build_diag_archive_script` so the empty-directory case became reachable at
all. A branch with no test because it is untestable is a distinct and more dangerous shape than
a branch someone merely forgot to test, and it will not show up in any coverage-gap review that
only counts untested lines. Worth sweeping the other Windows adapters for the same shape.

### QH-24 — The remote-script adapter layer is largely unreachable from tests, including its fail-closed paths
**Severity: high (it is the pool every other adapter defect is drawn from). Confidence: VERIFIED by inventory on `main` @ `1994ad01`; no refactoring attempted.**

The shape: a function takes a live connection, builds its remote PowerShell/shell script
**inline**, and executes it — so the script's *content* is unreachable from any unit test. Only
its call can be exercised, never what it says. Inventory by embedded-script line-continuations
per function (a proxy for how much untestable script a function carries):

| Function | continuations / fn lines | Why it matters |
|---|---|---|
| `windows_install.rs::deploy_relay_service` | **119 / 795** | largest single blind spot in the layer |
| `windows_install.rs::run_windows_e2e_bootstrap` | 76 / 177 | |
| ★ `windows_traffic.rs::cleanup_runtime_state` | 37 / 65 | **killswitch + NAT teardown** — residue here is a release blocker |
| ★ `windows_install.rs::enforce_daemon` | 35 / 79 | the **`auto_tunnel_enforce` fail-closed** path |
| `windows_install.rs::install_daemon` | 32 / 165 | the function that failed on signtool (QH-23) |
| `macos_install.rs::enforce_daemon` | 23 / 97 | same fail-closed path, other OS |
| `windows_traffic.rs::activate_exit_serving` | 13 / 35 | |
| `windows_traffic.rs::assert_mesh_client_nat_session` | 9 / 28 | produces release-blocking evidence — see below |

`windows_traffic.rs` contains only **three** extracted, testable script builders, one of which was
added while fixing QH-21. The same shape recurs in the `linux_*` and `macos_*` adapters, so this is
**adapter-layer-wide, not Windows-specific**.

★ **The reframing that matters:** the QH-21 `.Count` defect was not unlucky — it was drawn from a
large pool of script text no test can see. And two of the largest blind spots are exactly the
paths whose correctness we most rely on: the **killswitch/NAT teardown** (where residue is
release-blocking) and the **fail-closed enforcement** path on two operating systems.

Proposed direction: extract script builders as pure functions returning the script text, so the
text becomes assertable — the pattern already proven by `build_diag_archive_script`. Prioritise
the two fail-closed/teardown entries over the largest by line count. Do **not** mass-refactor:
inventory first (done), then extract where a real assertion follows.

### QH-25 — The NAT-session assertion is weaker than its own doc comment claims
**Severity: medium (it gates a release claim). Confidence: VERIFIED by hand-review of the script.**

`windows_traffic.rs::assert_mesh_client_nat_session` produces the `Get-NetNatSession` evidence for
the Windows exit cell — i.e. the artifact a release-blocking parity claim rests on. Hand-reviewed
because it is itself one of QH-24's untestable inline scripts.

Sound: `@()`-wrapped so `.Count` is safe; no StrictMode, so the `.Split`/property hazards are
muted; the mesh-range test (octet0 == 100, octet1 in 64–127, i.e. `100.64.0.0/10`) is correct;
retries 10 × 1500 ms; fails closed with an explicit `FAIL:` string.

★ **But it asserts that *some* mesh-sourced NAT session exists — not that it is the specific
client's mesh address.** That is a **range check, not an identity check**, while the doc comment
describes it as proving "a client's full-tunnel traffic". Unambiguous in a single-client topology,
materially weaker in any multi-client one, and the doc overclaims either way. Whichever way it is
resolved, a green result should be reported as *"a mesh-sourced NAT session was translated"* unless
the identity check is added.

Also: the pass message carries the concrete pair
(`OK nat_session <InternalSourceAddress> -> <ExternalDestinationAddress>`), so **that address pair
is the data block to report** — "the assertion passed" is not checkable evidence, the pair is.
Minor: a session with a null `InternalSourceAddress` makes `.Split` raise a non-terminating error
and skip that item (`$ErrorActionPreference` is `Continue` here); the assertion's verdict is
unaffected.

---

## The norm behind most of this list

Three times during this session a confident, well-argued finding was wrong: an
adversarial reviewer's headline root-cause claim, a dramatic claim about
false-green ledger rows, and two successive mechanisms proposed by the line that
owned the bug. Each was caught cheaply — by reading the cited code, checking the
archived artifacts, or running the payload.

The norm worth keeping: **a finding is not a finding until someone independently
reproduced it.** Correspondingly, a fix is not done until a test fails without
it. Most items above are instances of one or the other.

## Related documents

- `NodeEngineFlipDispositions_2026-07-24.md` — D1 carries the two_hop mechanism,
  the atomicity exposure behind QH-04, and the evidence-integrity note in QH-09.
- `TraversalSelfSustenancePlan_2026-07-23.md` — cross-referenced by QH-04.
- `HostObservabilityStabilityPlan_2026-07-24.md` — §7.10 names the confused-deputy
  threat model that QH-01 and QH-02 sit inside.
- `LinuxVmHostPlan_2026-07-14.md` — the remote-host lab work that surfaced QH-10.
- `CLAUDE.md` / `AGENTS.md` §3, §4, §7, §10.2, §10.4, §10.6 — the constraints
  these items enforce.
