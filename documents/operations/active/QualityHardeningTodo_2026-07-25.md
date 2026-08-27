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
> This register had **15** items at the 2026-07-25 review, not the 13 `README.md`
> then claimed; it has since grown to **43** (QH-01 through QH-43, contiguous).
> QH-39/40/41 were filed 2026-08-11 from the `percontrol-rebaseline-20260811`
> live run — one macOS false-green (mesh-status) plus one dead assertion (DNS),
> a rollback-ordering fail-open, and the lab-network drift that blocks every
> mixed-OS run. QH-39's framing and both its acceptance criteria were corrected
> the same day; read its inline notes before implementing it.

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

★ **THE ROOT CAUSE, IN ONE SENTENCE** — formulated 2026-07-26 by the line that hit this shape
**twice in one day**: once as the reviewer who caught it in another branch, once as the author
who committed it in their own.

> **A test that constructs the value it's checking, instead of calling the code that constructs
> it, will always pass.**

That is the entire mechanism. Both instances *looked* thorough: import the validator or the
quoter, rebuild the map/join inline, assert on the result. Neither touched the production
function, so reverting production left them green. The tell is **not** weak assertions — those
were fine — it is that **the test owns the construction**. The signature to look for is an import
of the primitive plus a local re-implementation of what production does with it. That it caught
the same author from both sides is the strongest evidence that the *shape* is the hazard rather
than any individual's care.

★ **Corollary, which caught a different line the same day:** *a change whose only proof is a green
live run has no regression guard at all.* A live run proves behaviour once, on one topology, at
one commit; it cannot fail when someone reorders the code six weeks later.

★★ **The inverse, and the strongest argument for writing the test at all: a test written to CONFIRM a
belief can REFUTE it — including a belief you have already shipped.** Measured instance: a reviewer
asserted that `Debug` escapes neither `Cf` bidi overrides nor `Zl`/`Zp`, the coordinator relayed it as
fact, and an author committed a code comment and a commit message repeating it. Writing the test to
prove the resulting extension made the test **fail**, and direct measurement showed `Debug for str`
escapes by **printability rather than by control category** — so it escapes `U+202A`, `U+202E`,
`U+2028`, `U+2029`, `U+200D` and `U+FEFF` alike, and `{value:?}` is a complete terminal control on its
own. Three parties had propagated the false claim; the assertion caught it.
The rule: **encode a claim as an assertion and it becomes checkable — and that applies to claims from
reviewers, and from the coordinator, exactly as much as to claims from the author.** Note the
resulting test was then rewritten to pin the *corrected* reasoning (asserting that `Debug` **does**
escape these), so if that behaviour ever changes the fallback control becomes load-bearing and the
test says so. A test that documents which control is actually doing the work is worth more than one
that merely passes.

Related, same session: **an error string another test matches on is an interface.** Rewording
`"unsupported control characters"` broke `bootstrap_script_rejects_control_characters`, and neither a
stale full-lib run nor the author's targeted groups could see it — only the authoritative workspace
sweep did.

★★★ **THE CAPSTONE — why this item exists at all.** On the false `Debug`-escaping claim, the
attribution matters far less than the propagation: it passed through **a reviewer**, through **the
coordinator**, and through **the author** into a committed code comment *and* a commit message.
**Three review checkpoints, none of which caught it — because none of them was a machine check.**
The assertion caught it on **first execution**.
That asymmetry is the entire argument of this register: prose review, however careful and however
many people it passes through, does not converge on truth the way a single executed assertion does.
So the working rule is to **over-encode claims as tests rather than argue them in prose** — and to
treat any safety claim that has *only* been reviewed, no matter by how many parties, as unverified.

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

★ **Third instance, and it cost two investigation cycles: `wg show` FAILS on a userspace
shared-transport node.** A capture read `wg show rustynet0 allowed-ips` on every sampled host and
recorded `aips=[]` for the final exit on every sample — which was read as *"that node has no
WireGuard peers"* and briefly became a leading hypothesis for a dataplane failure. It was neither:
`wg show` exits **1** there, because that node runs the **userspace shared-transport** backend and
has no kernel WireGuard device to query. The daemon's own status showed both peers correctly
programmed. This is the same property that makes `path_live_proven` unsatisfiable on shared-transport
nodes while the kernel-backend node answers fine.

The generalisable rule, which is the whole point of this item: **an instrument that can fail must
have its failure distinguished from its negative result.** `aips=[]` conflated "queried, found none"
with "the query failed" — and a capture that records only the parsed value, discarding the exit
code, cannot tell them apart. Record the tool's exit status alongside its output, and treat a
non-zero exit as *unknown*, never as *empty*.

Proposed fix: readiness and reachability checks assert the protocol actually
required (a TCP connect, or a real SSH session), never ICMP; and any probe that
is known to produce false negatives in a given environment says so at the point
of use. Any probe reading a tool's stdout must also capture and act on its exit code.

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

★ **THIS IS A FAMILY, NOT A ONE-OFF — four instances in a single session, each one a tool
reporting success while doing nothing or reading the wrong thing.** Collected here because the
shared lesson is stronger than any single case: **read the count, not the word `ok`; read the
tool's own exit code, not the pipeline's; and prove the reader parses what you think it does.**

1. **Pipeline swallows the exit code.** `cargo test … | tail -60` exits with **`tail`'s** status.
   Invalidated a reported-green workspace gate; the truncated tail also under-reported the test
   count by two orders of magnitude (27 vs ~10,000).
2. **`awk -F,` on the lab CSVs reads the wrong column**, because every row carries quoted
   comma-bearing fields. Produced a confidently wrong "no `pass` rows" conclusion which was then
   used to **overturn a correct finding** (see QH-07).
3. ★ **A test filter that matches nothing still prints `ok`.** `cargo test` reported
   `0 passed; 0 failed … ok` because `ops_e2e` is declared in **both** `lib.rs` and `main.rs`, so
   without `--lib` the filter matched no target. A test suite that ran zero tests is
   indistinguishable from a green one if you read the word rather than the number.
4. ★ **An unquoted `$VAR` in zsh doesn't word-split**, so a multi-file `grep "$FILES"` searches one
   bogus filename, fails, and the failure reads as "clean". Produced a false all-clear on a
   credential scan of files about to be pushed to a **public** repo.
5. ★★ **A task-completion notification reported "exit code 0" for a run whose `cargo test` exited
   `101` with a failing test.** The notification carries the **wrapper's** status, not the tool's.
   Only an explicitly captured `WORKSPACE_TEST_EXIT=101` revealed it — and the branch was one
   message from being reported READY TO INTEGRATE. This is the most dangerous member of the family
   because the false signal arrives at the *coordinator*, who is furthest from the evidence and most
   likely to treat "exit code 0" as authoritative. **A completion notification is not a gate
   result.** Require the tool's own captured exit code, quoted, in the report.

6. ★★ **A git pipeline's later steps silently operated on the wrong content.** A
   `git stash` → `reset --soft` → `stash pop` sequence had the **pop fail mid-pipeline**
   (`local changes would be overwritten`, stash retained) — and the three recommits that followed
   captured the **unfixed** file. Caught only by inspecting the artifact (`git show <commit>:file`)
   rather than trusting that the command sequence had done what it reads as doing.
   Specifically: **`git stash pop` after `reset --soft` is unsafe**, because the reset
   re-materialises the same paths as local changes, so the pop cannot apply. Generalised:
   **check the artifact, not the command sequence.**

Countermeasures that actually work, all used successfully afterwards: capture the tool's own exit
code with no pipeline in the path; assert on the parsed **count**; add a **positive control** —
a pattern that MUST match, so a silent no-op is visible; distinguish grep's exit codes
(`0` found / `1` clean / other = **error, do not trust**); and after any multi-step git
manipulation, verify the committed content with `git show <commit>:<path>` before reporting.

★ **A corollary that caught the same line twice in one cycle: a comment-only edit is NOT inert.**
Under `-D warnings`, reformatting a doc comment tripped `clippy::doc_lazy_continuation` (a closing
paragraph following a bullet list with no blank `///` separator) and took clippy to **exit 101 with
3 errors**. It was caught only because gates were re-run after a restructure instead of assuming
prose couldn't break a build. Re-run the gates after documentation changes too.

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

★★ **CORRECTION 2026-07-26 — "per-host exclusion" is the WRONG unit, and this item's own framing
(the coordinator's) would have regressed a documented workflow.** Concurrent runs on **one** host are
**intended**: `ai_agent.rs:421` sets `MAX_CONCURRENT_LAB_RUNS = 3`; `:3760-3779`'s `allow_concurrent`
raises the cap and its own refusal text instructs callers to pass it *"AND disjoint guests"*; `:3828`
gives each run its own `CARGO_TARGET_DIR`; and `CLAUDE.md` §12.5 documents "≤3 overlapping" for the
macOS↔Windows pipeline. A per-host lock would break parallelism the project deliberately built.
**The hazard is guest contention, not host occupancy.** The exclusion unit must be the **resolved
guest-alias set** — refuse a run whose guests overlap an in-flight run's, allow disjoint sets through.
Two further design constraints, both verified:
- **Lock at `main.rs:8440 execute_ops`, not at the individual functions.** Three existing tests call
  the would-be-locked functions directly (`mod.rs:53694`, `:46211`, `:46284`) and nextest runs one
  process per test, so locking at function entry would make unit tests contend on real production lock
  state. `execute_ops` is a clean chokepoint: one caller, zero test callers, every invocation form
  reaches it.
- **Use `flock`, not a pidfile.** The kernel releases it on process death, so there is no recorded pid
  to argv-verify and the stale-lock and pid-recycling classes vanish. The repo already has this shape
  at `live_lab_run_matrix.rs:2216`. (The argv-verifying pidfile remains correct for the **stop** path,
  which must signal a pid it did not create.) Verified on Darwin: flock conflicts across two separate
  `open()`s in the *same* process (errno 35), so it must be taken exactly once per process — which the
  chokepoint gives for free.
**Residual accepted deliberately:** closing the false *negative* removes the dangerous direction. The
false *positive* — `pgrep` self-tripping on an inline-over-SSH launch — stays open, because closing it
means editing `script_template.rs:697`/`:2144` plus the two assertions pinning that string
(`mod.rs:54748`, `:54866`) in a file that just landed. An annoyance is not worth disturbing a settled
security boundary.

Proposed fix: replace the pattern match with a real mutual exclusion — a pidfile or lockfile
whose liveness is confirmed by checking the recorded pid's identity (this repo already has a
pid-recycling-safe guard for the *stop* path that argv-verifies before signalling; the same
approach applies here), or an flock on a per-host lock path. Whatever is chosen, it must not
be satisfiable or defeatable by the shape of the caller's command line.

Acceptance: launching inline over SSH does not self-trip the gate, **and** a second launch
is refused while a real run is in flight regardless of how either was invoked.

★★ **UPDATE 2026-08-27 (STOP-PGREP) — the same self-match existed on the STOP path, where the
consequence is a signal, not a refusal, and it is now closed.** The "residual accepted
deliberately" note above scoped the surviving false positive to the *launch* gate. It was not
the only site: `HOST_STOP_SCRIPT` unioned a
`pgrep -f 'vm-lab-orchestrate-live-lab'` result into its candidate pids, and that script is
driven inline over SSH by `execute_ops_vm_lab_stop_host_run`, so its whole text — including the
subcommand string the pattern searches for — sat in the remote `bash -c` argv. The launch-side
false positive costs a wrong refusal; here the very next statement is
`kill -TERM -- -<pid>` on the matched pid's **process group**, so a stop on an idle host could
signal its own launcher, and on a busy host could take down an unrelated shell that merely had
the string in its argv.
The pattern scan is removed rather than rewritten, for the same reason it was removed from the
launcher: the script must contain the string it searches for. The recorded pidfiles are now the
only source of candidate pids, which the argv-liveness-checked prune in `HOST_LAUNCH_SCRIPT`
makes trustworthy — a live run always has a recorded handle. Each recorded pid must clear two
guards before it is signaled: it is not this shell or any of its ancestors, and its argv still
contains the orchestrator marker (a `ps -p <pid>` lookup of one named pid, never a scan). With
no live recorded pid the script signals nothing, prunes the stale handles, and says so.
Pinned by `vm_lab::stop_host_run_tests` — `the_stop_script_contains_no_self_matching_process_scan`,
`stop_never_signals_itself_or_an_ancestor`, and a behavioural test that runs the rendered script
under `bash -c <script>` (reproducing the inline-over-SSH argv) in its own process group and
asserts nothing is signaled.

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
to explain away a red suite.

★★ **CORRECTED AND FIXED 2026-07-26 — the stated mechanism was WRONG, and the truth is worse than
flakiness.** It does **not** depend on name resolution: `ssh_target` is rewritten to the
utmctl-discovered IP before any probe runs, so `alpha-host` was never resolved at all. Measured by
watching the test's children: ~90 s with no child process (three × 30 s **TCP** timeouts inside
`probe_tcp_port_status`), then a 15 s **real `ssh`** invocation.
★ **The actual finding: the fixture used `192.168.64.8` — this Mac's live UTM bridge subnet, where
`192.168.64.20` is a real lab guest.** So a *unit test* was opening TCP connections and SSH sessions
against an address range that hosts live lab VMs. That is a test reaching out of its sandbox into the
running lab, not merely a slow test.
Fixed by repointing at TEST-NET-1 / `.invalid` with a bounded timeout, matching the sibling test
below it: **106 s → 6.7 s**, outcome now environment-invariant, and still sensitive (forcing
`process_present = true` turns it red).
Generalisable check worth applying elsewhere: **grep the test fixtures for addresses inside the lab's
live subnets.** A test that happens to target a real guest passes or fails on what that guest is doing.

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
**Severity: medium. Confidence: VERIFIED.**

> **RESOLVED 2026-08-10, FORWARD-ONLY.** Both halves now select the chronologically first
> failure. The verifier half landed earlier; the ledger half landed in `b5286769` (plus
> follow-ups) — `StageEvidence` gained `started_at` from `stages.tsv` column 6 and
> `first_failed_stage` selects with the verifier's key `(is_blank, started_at, stage)`, empty
> sorting LAST. Plan and full review record:
> [`QH22LedgerChronologyPlan_2026-08-10.md`](./QH22LedgerChronologyPlan_2026-08-10.md).
>
> **The text below is preserved but two of its claims are now stale.** (1) "The computation is
> correct, the naming is the defect" was true when written and is no longer the whole story:
> the verifier was subsequently made chronological while the ledger was not, so the two
> producers of one field came to disagree *by construction* — which is why the fix emits a
> genuinely chronological value rather than renaming the field. (2) The described verifier
> behaviour ("selects the first `Fail` while iterating `merged`… in key-sorted order", cites
> `:529-532`, `:428`) has not described the code since the verifier half landed.
>
> **Forward-only:** the 90 populated rows extant at the fix keep their alphabetical values and
> were not rewritten. The column carries mixed semantics across the boundary commit — do not
> compare it across that boundary, and do not read a pre-fix row as chronological.
>
> **Evidence.** 8 ledger + 2 verifier tests. Mutations verified to discriminate: revert to the
> alphabetical `find` (1 vs 8 ordering), invert the empty-sorts-last comparison, restore the
> status-blind time merge at each site independently. Two defects found by adversarial review
> of the *implementation* and fixed before landing: the higher-rank merge arm erased a real
> timestamp when the winning record carried none (reintroducing this very misdirection), and
> `not_proven` — ranked WITH `fail` — satisfied neither consumer's literal `"fail"` test, so a
> merged `not_proven` made a failed run report NOT-failed. Both pinned by tests.
>
> **Adjacent, still open:** the QH-37 rank fix was never mirrored — `status_rank` ranks
> `skip`(4) above `pass`(3) while the verifier's `StatusClass::rank` ranks `Pass`(4) above
> `Skip`(3). Unreachable for *this* field (`fail` is rank 8 in both) but a live divergence one
> function away. Also: most triage tooling (`lab_state.rs`, `ai_agent.rs`, the flake report)
> reads the FROZEN bash archive, so this fix does not reach it — notably the auto-retarget at
> `ai_agent.rs:1722-1732`, which picks the next lab cell from this field.

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

### QH-26 — Three unreviewed delegated-edit WIP checkpoints are on `main`, one of which deleted a trust check and silently repurposed its own negative test
**Severity: HIGH as a process failure. Confidence: VERIFIED end-to-end.**
**★ Do NOT simply revert `f1ef83b1` — read the direction finding below first.**

`documents/…/CLAUDE.md` §12.6 states that a delegated-edit job's branch is **never merged back**, and
that "reviewing and merging that branch is a human step — that is the actual security checkpoint."
That checkpoint was bypassed. Three commits whose own message reads *"Committed by the
delegated-edit tier because the job ended before the agent committed. **Review before merging.**"*
are reachable from `origin/main`, all dated 2026-07-20, all touching `crates/rustynetd/` — the
trust-path crate:

| commit | shape |
|---|---|
| `f1ef83b1` | `daemon.rs` −14, `phase10.rs` −7 — **the only one that removes anything** |
| `f54edda5` | `daemon.rs` +57/−1 — additive |
| `15cf9f11` | `daemon.rs` +56 — purely additive |

**What `f1ef83b1` removed:** the `tls13_valid` field from the trust-evidence structs, **two**
enforcement points (`daemon.rs:2345-2347` `"trust evidence tls13_valid=false"`, and
`phase10.rs`'s `TrustRejected("tls13_not_valid")`), and the evidence-file parser's
**required-key** check (`missing tls13_valid` → `InvalidFormat`). On `main` today a single `tls13`
reference survives, a leftover fixture string at `daemon.rs:21499`.

★ **DIRECTION FINDING — the deletion is probably CORRECT, and reverting would restore security
theatre.** The audit `DocCodeDiscrepancyAudit_2026-07-18.md` DA-01 (**Critical**) had already
established that this field was **hardcoded `true` at issuance regardless of any real transport** —
every producer emits the literal `tls13_valid=true`
(`rustynet-cli/src/main.rs:8075`, `bin/rustynet-windows-trust-cli.rs:271`,
`vm_lab/orchestrator/adapter/windows_install.rs:935`, plus test fixtures), and verification merely
checked that the string parsed back as `true`. The audit's words: *"a second self-asserted,
non-enforcing TLS claim layered on top of the original one — the gap has widened, not narrowed."*
No crate depends on a TLS library for the control plane. So the removed "control" asserted nothing,
and deleting it makes the code **more** honest. This is the *diagnose-direction-before-fixing* case:
a vanished check is not automatically a regression.

**The real defects, therefore, are process and honesty rather than a missing control:**
1. **An explicitly-unreviewed WIP checkpoint reached `main`** and mutated the trust path. Whatever
   its content, that is the review gate failing, and it happened three times.
2. **The negative test was silently repurposed, not retired.** `tls13_valid: false` →
   `signed_control_valid: false`, so the suite stays green and the removal is invisible — QH-02's
   pattern again, this time hiding a deliberate change rather than a bug.
3. **No rationale, no ledger entry, no link to DA-01.** A future reader sees a fail-closed check
   disappear under a message that says "WIP".
4. ★ **The doc/code gap has now inverted.** `SecurityMinimumBar.md` still claims "TLS 1.3 enforced
   for control-plane APIs". The code got more honest; the document did not. DA-01 remains open and
   is now the substantive item — **either implement real control-plane TLS or correct the claim**.
   That is a change to a stated security property in the minimum bar, so it is an **operator
   decision**, not an agent one.

Acceptance: (a) `f1ef83b1`'s content is either confirmed-and-documented (rationale, DA-01 link, an
honest test that fails for the right reason) or reverted on the merits — decided deliberately, not
by default; (b) the two additive checkpoints are reviewed on their merits; (c) something prevents a
"Review before merging" commit reaching `main` again; (d) DA-01 is resolved by the operator.

### QH-27 — Rebasing across a moved base while holding uncommitted work silently reverts other lines' commits
**Severity: medium-high (data loss, and it nearly landed twice). Confidence: VERIFIED — two independent near-misses in one session.**

With several lines integrating in parallel, `origin/main` moves under work-in-progress. Two
distinct near-misses, both caught only because someone checked deliberately:

1. A line held an older copy of `QualityHardeningTodo_2026-07-25.md` in its working tree. After a
   soft reset across a moved base, that stale copy presented as a **modification**, and committing
   it would have **reverted the register entries another line had just landed** — silently, with no
   conflict. Avoided by taking `origin/main`'s version for every file `main` had changed before
   committing.
2. The same shape from the opposite direction: taking a **remote host's** working copies of the
   three evidence ledgers to harvest appended rows. The box sat at `b7667cce` while `main` had
   moved to `9fd68a07`, so a blind copy would have dropped the rows appended in between. Avoided by
   diffing the host's ledgers against `main` first and confirming they were byte-identical, so the
   copy could only add.

Neither case produces a merge conflict, because in both the file is *whole* and merely older —
which is exactly why it is dangerous. Append-mostly shared files (the run matrix, stage results,
the triage jsonl, and any register or ledger several lines write) are the exposed surface.

Practice that caught both, and should be the rule: **before copying or committing a whole file that
another line may have touched, diff it against `origin/main` and confirm you would only ADD lines,
never remove them.** A "lost lines" count of zero is the check; if it is non-zero, inspect every one
before proceeding. Prefer targeted edits over whole-file copies for shared documents, and re-fetch
immediately before any push.

### QH-28 — The Windows installer script is SHARED with the shipped product, and on that path it mints a self-signed code-signing cert into `LocalMachine\Root`
**Severity: HIGH (trust-store modification on an end-user machine). Confidence: VERIFIED by code read.**
**★ OPERATOR DECISION — do not "fix" this autonomously. It is a design question about a shared script, not a bug with an obvious correct answer.**

`scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1` is embedded in **two** places:

- `crates/rustynet-cli/src/install/live_windows.rs:27` — the **shipped** installer
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs:48` — the lab path

`install/mod.rs:19` declares `mod live_windows;` with **no cfg gate** and `main.rs:5` pulls in
`mod install`, so it is in the **default build** — not behind `vm-lab`, not lab-only.
`live_windows.rs:207` writes the embedded script and invokes it with no switch that skips signing,
and the signing block (~`:898`) is top-level, so it runs on **every** invocation.

★ **The finding that needs an operator, not an agent:** that block's own comment states it "never
leaves the lab guest" — and that is false, because the shipped path executes it. On that path it
**mints a self-signed code-signing certificate and installs it into `LocalMachine\Root`**, i.e. the
machine-wide Trusted Root store on an end user's computer. Consequences to weigh, none of which an
agent should decide alone: anything signed with that key becomes trusted machine-wide; the key
material's location and lifetime on the user's machine matter; and the reassurance in the comment is
exactly the false-safety-claim pattern of QH-05, here guarding the most consequential behaviour in
the file.

Two consequences that are settled and actionable now:

1. **A lab-motivated edit to this script is a PRODUCT change.** The arm64-first signtool defect
   (QH-23) lived here, so its fix touches the shipped install path. Review it as such, and consider
   whether it warrants a release note. Bounding the blast radius honestly: the defect only bites
   where a Windows SDK is **present** with an `arm64` subdirectory — on a clean end-user machine
   with no SDK the old code already threw "SDK not found", so the real-world exposure was
   developer/build machines, and the fix strictly improves both cases. The relevant sharpener is
   that release ships **`x86_64-pc-windows-msvc` only**, so every shipped Windows target is exactly
   the architecture the old ordering broke.
2. ★ **The two installer copies propagate by DIFFERENT mechanisms**, which matters for verifying any
   fix to either: the daemon installer is `include_str!`-embedded, so it ships only via a **rebuild**
   (cargo does track the `.ps1` — touching it triggers a recompile, verified); the relay installer is
   **not** embedded and is resolved from the source root at runtime (`ops_e2e.rs:1662`), so it
   propagates via the **guest source sync**. A stale binary hides a daemon-side fix; a stale guest
   source tree hides a relay-side one. This also means QH-23's pinning test is doing more work than
   credited — it holds two copies identical across two different delivery mechanisms.

Acceptance: (a) the operator decides whether the shipped path should mint and trust a self-signed
cert at all, and the comment is corrected to describe what actually happens on each path; (b) edits
to this script are recognised as product changes in review; (c) any future divergence between the
two copies fails a test rather than a live run.

**Open, deliberately not decided by an agent: does the signtool-architecture fix warrant a release
note?** The fix touches the shipped install path, and the defect it corrects could select an
unrunnable signtool on any x86-64 machine that has a Windows SDK present — i.e. developer and build
machines rather than clean end-user installs. Whether that reaches a release note is a
release-process judgement. The landing commit carries a `NOTE FOR RELEASE REVIEW` header stating the
shared-embedding fact so a release reviewer sees it without tracing `mod install`, and explicitly
leaves this question open rather than answering it.

### QH-29 — A fail-closed runtime self-assertion that pattern-matches generated config couples that config's *formatting* to daemon liveness
**Severity: medium (latent, fleet-wide blast radius). Confidence: VERIFIED — the hazard was checked and found benign, but only by looking.**

Adding a `counter` to the two hairpin nftables rules — a **pure observability change** with no
behavioural effect — came within one implementation detail of failing the daemon closed on **every
exit-serving node**.

`assert_nat_forwarding` is a runtime killswitch self-assertion: it verifies the *live* ruleset
contains `["iifname", iface, "oifname", iface, "masquerade"]`. Inserting `counter` changes the
rendered line to `… oifname "rustynet0" counter packets 0 bytes 0 masquerade`. Had that matcher
required the tokens to be **adjacent**, the assertion would have failed against a correct ruleset,
and the node would have fail-closed — correctly, by its own logic, on a change that altered nothing
about forwarding.

It is safe because `chain_contains_all_tokens` (`phase10.rs:1160-1163`) tests each token as an
**independent substring** rather than as a sequence. That is load-bearing and was previously
undocumented; it is now noted at both rule sites so the matcher cannot be "tidied" into adjacency
without seeing what depends on it.

★ **The generalisation, and the actionable part:** wherever a fail-closed runtime assertion
**string-matches generated configuration**, the config's *textual format* becomes part of the
liveness contract — so a formatting-only edit can take a fleet down, and nothing in the type system
says so. Two rules follow. First, before editing generated config text, grep for runtime assertions
that match it. Second, **sweep for other instances**: any other self-assertion that pattern-matches
rendered nft/route/systemd/registry output has the same coupling, and each one wants the dependency
documented at both ends — the matcher and the generator.

Worth pairing with QH-24: assertions over *generated text* are exactly the shape that is hard to
test, because the test usually re-renders the text rather than exercising the live matcher.

### QH-30 — Coverage that existed only as a side-effect of a bug disappears when the bug is fixed, silently
**Severity: medium-high (a fail-closed branch is now wholly uncovered). Confidence: VERIFIED.**

The `extra_peers` fail-closed branch (`daemon.rs:6730-6739`) — the one that rejects a traversal
snapshot containing peers the assignment does not manage — had **no test**. It was nonetheless
exercised end-to-end on every `two_hop` run, but only **by accident**: the stage's non-atomic bundle
swap kept producing exactly that inconsistent state, so the branch fired constantly and its
correctness was continuously demonstrated as a side effect of a defect.

Fixing the defect (the atomicity fence) removed the only thing exercising it. The branch is now
covered by **neither a live run nor a unit test**, while its sibling — the `missing` direction — is
pinned at `daemon.rs:26328`. Nobody would notice, because it *used* to be well exercised.

★ **The generalisable risk, stated by the line that found it:** *a fail-closed branch whose only
historical proof was an accident of a broken test topology is one refactor away from silently
becoming fail-open.* And the reason it evades every normal check: coverage tooling sees a branch that
was recently and repeatedly executed, ledgers record it passing, and nothing flags that the
*mechanism* which executed it has been deliberately removed.

Actionable: whenever a fix removes an error condition that used to occur routinely, ask **what was
that error condition exercising, and does anything still exercise it?** Then sweep for other branches
whose only exercise is incidental — likely candidates are error paths that fire because of a known
defect, and negative branches reached only via a misconfiguration the project is actively fixing.

A precise spec for the missing test is recorded on the two_hop line's ledger: mirror the multi-peer
snapshot test with the traversal index a strict **superset** of the assignment peer set; assert the
"unmanaged peers" failure names the extra peer and that `restriction_mode`/`reconcile_failures`
advance. It was deliberately **specced rather than half-built**, on the sound reasoning that a
half-built negative test is worse than a documented gap — it looks like coverage.

**CLOSED 2026-08-22 (wave1/qh30):** both live `extra_peers` fail-closed sites are now pinned by unit
tests in `crates/rustynetd/src/daemon.rs` — `daemon_runtime_auto_tunnel_traversal_authority_fail_closes_on_unmanaged_peers`
(bootstrap-time apply gate, `apply_traversal_authority_to_peers`; asserts the apply-specific wrapper
"traversal authority rejected bootstrap apply: traversal authority snapshot contains unmanaged peers: node-stray")
and `daemon_runtime_auto_tunnel_traversal_runtime_sync_fail_closes_on_unmanaged_snapshot_peer`
(runtime-sync gate via `refresh_traversal_hint_state` after a valid bootstrap; asserts
"traversal runtime sync failed" + `DataplaneState::FailClosed`). Each test was mutation-proven in
isolation: neutering only the apply-site check fails only the first test; neutering only the
sync-site check fails only the second (the stray peer is Active in membership so the earlier
membership gate passes and cannot mask either site).

**Related, from the same retraction cycle — an inference rule worth keeping:** *counter arithmetic can
bound magnitudes but cannot localise a drop across a netfilter hook upstream of the counter.*
`IPSTATS_MIB_OUTFORWDATAGRAMS` increments in `ip_forward_finish`, downstream of `NF_INET_FORWARD`, so
a packet dropped in the FORWARD chain is never counted — which is why a forwarded-packet count could
not distinguish "replies never arrived" from "replies arrived and were dropped". The coordinator
endorsed that arithmetic as decisive; it wasn't.

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

### QH-31 — The lab monitor reports "idle" while an orchestrator is visibly running, because ad-hoc run discovery resolves `--report-dir` against the TUI's own cwd
**Severity: medium (an operator watching the TUI cannot tell a live run from a dead one). Confidence: VERIFIED live 2026-07-29 against `f22be5af`, during the first run of the triage launch gate.**

A real `vm-lab-orchestrate-live-lab` run was in flight — 30 stages recorded, guests
being driven over SSH, `state/stages.tsv` updating every few seconds — and the TUI
showed **idle**. The operator reasonably concluded the run had crashed.

All three of `find_running_jobs_with_live_processes`'s discovery paths missed it:

1. **Process-table discovery** (`job_watcher.rs:226-252`) exists precisely to catch
   this case; its own doc comment says it is there "so an ad-hoc CLI-launched run is
   found even when it has no job-state JSON". It takes the `--report-dir` value
   **verbatim from the command line** and immediately does `if !dir_path.is_dir()
   { continue; }`, with no `repo_root` join. A **relative** `--report-dir` therefore
   resolves against *the TUI's* working directory. `rustynet-lab-monitor` is
   workspace-excluded and is launched with `cd crates/rustynet-lab-monitor`, so
   `artifacts/live_lab/<run>` does not resolve there and the live run is skipped.
   Measured: same path resolves `YES` from the repo root, `NO` from the TUI's cwd.
2. **`state/` orphan scan** (`:173-219`) only walks `repo_root/state/`; a report dir
   anywhere else (`artifacts/`, `/tmp`, a lab-reports dir) is invisible to it.
3. **No job-state JSON**, because the run was launched from the CLI rather than
   through `start_live_lab_run`.

Each path individually has a defensible reason to miss it. Together they mean the
*normal* way a human launches a run — relative `--report-dir`, straight from the
CLI — is the one combination nothing detects.

**Fix direction (not started):** resolve a relative `--report-dir` against the repo
root (or against the orchestrator process's own cwd, readable on macOS via
`lsof -a -p <pid> -d cwd` and on Linux via `/proc/<pid>/cwd`) before calling
`is_dir()`. A regression test should pin a *relative* report dir specifically —
`parse_orchestrator_processes` is already isolated for exactly this kind of test,
and every existing case presumably passes an absolute path, which is why this
survived.

★ **Generalisable:** this is the mirror image of the earlier candidate finding that
the TUI shows a *phantom live run* when `pid` is null (`unwrap_or(true)`). Same
module, same class — **liveness inferred from a signal that can silently fail to
resolve**, failing open in one direction and closed in the other. Worth auditing
both directions together rather than patching whichever one was last observed.

**Do not mistake this for a run failure.** The ground truth while a run is in
flight is `<report_dir>/state/stages.tsv`; the TUI is a view over job discovery,
not over the run itself.

---

### QH-32 — A live-lab run prints nothing to stdout for its entire duration, so "working" and "hung" look identical
**Severity: medium (drove a false crash diagnosis; worse for remote runs). Confidence: VERIFIED 2026-07-29.**

`vm-lab-orchestrate-live-lab` emits a handful of banner lines at launch and then is
silent for the whole run — ~10 minutes here, 30-45 for a full suite. All progress
goes to `state/stages.tsv` and per-stage log files under the report dir. From a
terminal there is no way to distinguish a healthy run from a wedged one without
knowing that file exists and reading it out of band.

The seam already exists: the `RustNativeStageRecorder` observer in
`orchestrator/native.rs` is notified on every stage start and finish and upserts
those rows today. Teeing one line per transition to stderr is nearly free.

This compounds QH-31 (the TUI, the other way of watching, was simultaneously
showing idle) and matters more for the remote host, where there is no terminal to
glance at and `host_run_status` reads the same ledger.

---

### QH-33 — Several `vm_lab` unit tests perform real network I/O against the live lab subnet, making the full suite intermittently red and ~5 minutes slower
**Severity: medium (a flaky gate is a gate nobody trusts). Confidence: VERIFIED — six full-suite runs 2026-07-29.**

Across six `cargo nextest run --workspace` runs, **five different** `vm_lab` tests
failed on different runs, each passing in isolation. Two contributing causes:

- **Fixed (`7b0310d5`), but not the dominant one:** 17 tests built temp paths from
  `SystemTime::now().as_nanos()` alone. nextest runs a crate's lib and bin test
  targets as two processes over the same test list in lockstep, so both could derive
  the same directory and one's `remove_dir_all` deleted the other's mid-test —
  surfacing as failures on `fs::write`, not on assertions. All 17 now use
  `unique_suffix()`, which also gained a pid field.
- **Open, and dominant:** several tests do **real TCP probes against
  `192.168.64.0/24`** — the live lab subnet — with short timeouts. One uses
  `timeout_secs: 2`; three `execute_ops_vm_lab_discover_local_utm_*` tests take
  ~106 s each waiting on connects and alone account for roughly five minutes of
  every full-suite run. Timing that tight is not deterministic under nextest's
  global concurrent pool, and the result depends on what is powered on in the lab.

**Fix direction:** inject the probe behind the seam these tests already use for
`utmctl` (they pass an `utmctl_path` to a fake script; the TCP probe has no
equivalent). That fixes the flakiness and the runtime together.

---

### QH-34 — Every run records `dirty:worktree` because the run itself mutates a tracked file that the dirty-state exclude list does not cover
**Severity: low-medium (devalues the provenance field on every evidence row). Confidence: VERIFIED 2026-07-29.**

The run at `f22be5af` started from a **clean, committed tree** — `host_preflight`
reported `local_clean PASS` moments before launch — yet its run-matrix row records
`dirty:worktree`. The orchestrator legitimately refreshes
`documents/operations/active/vm_lab_inventory.json` (live-IP updates) during the
run, and unlike the three ledger CSVs and the triage JSONL, that path is **not** in
the `:(exclude)` list used by the dirty-state check
(`live_lab_run_matrix.rs:1425-1436`, `vm_lab/mod.rs:28931-28942`).

So the field cannot distinguish "operator ran with uncommitted edits" — the thing
it exists to warn about — from "the orchestrator updated the inventory, as designed".
A provenance flag that is always set carries no information.

**Decide, do not just add an exclude:** either exclude the inventory (accepting that
a hand-edited inventory then goes unflagged), or sample dirty-state *before* the run
mutates anything and record that. The second preserves the signal; the first is a
one-line change. Worth checking whether any historical `dirty:*` reading is
trustworthy before relying on one.

---

### QH-35 — The privileged-helper allowlist and the code that builds the argv are tested only against themselves, so a shape mismatch stays invisible until the feature is switched on
**Severity: medium-high (one instance was a live traversal-path denial, one blocks a
release-gated feature). Confidence: VERIFIED 2026-08-07, both instances fixed in
`16de276f`.**

`validate_wg_args` (`privileged_helper.rs`) is an exact-match allowlist with a deny
catch-all, and `PrivilegedCommandClient::run_capture` runs it **client-side, before
the socket**. So any argv shape the backends build but the allowlist does not name is
not a helper-side rejection — it is a `BackendError` on the caller's own thread.

Two such shapes existed simultaneously, and **each half's own tests passed**:

1. **`persistent-keepalive <n>` (FIS-0015).** All three command backends append it the
   moment `PeerConfig::persistent_keepalive_secs` is `Some`. Latent only because the
   field defaults to `None` — switching the adaptive-keepalive rollout on would have
   failed peer configuration outright rather than degraded to no keepalive.
2. **The endpoint-only `set <iface> peer <key> endpoint <ep>` re-point**, which
   `update_peer_endpoint` emits with no `allowed-ips` tail. **Not** gated behind an
   off-by-default field: it is reached from the traversal path in `phase10.rs` whenever
   a peer is promoted to a directly reachable address, on both the Linux and macOS
   command backends. Open question worth answering: which `DaemonBackendMode` the
   traversal-proven live runs used, since the userspace-shared backends bypass this
   validator entirely and would mask the failure.

The structural point is that neither backend tests nor validator tests can catch this
class — only a test that drives one against the other can, which is what
`allowlist_accepts_every_argv_the_linux_backend_emits_with_keepalive_enabled` now does.
**Before adding any new `wg`/`ip`/`pfctl` invocation, or any new optional field that
appends a token, check the allowlist arm in the same change.** Widen it deliberately
and keep the token guards: the boundary is exact, not a prefix match, and the shipped
adversarial corpus in `privileged_helper_allowlist_audit.rs` must gain matching
allow *and* deny cases so the check also holds on deployed binaries.

Note `wg show <iface> dump` is still absent from the allowlist by choice — its only
caller invokes `wg` directly rather than through the helper, so it has no caller behind
it yet. It will need an arm when the endpoint-attribution work lands.

---

### QH-36 — Gossip peer registration is additive-only, so a node's key rotation leaves the OLD key registered for the process lifetime and revocation removes only the NEW one

**Verified against `58b19ce4`.** Raised by the review of
`GossipProducerAlignmentIncrement1_2026-08-08.md`, which cannot land until this is
filed, because that increment *is* a key change for every already-provisioned node.

Three facts, each read:

- `daemon.rs:5507-5511` documents the behaviour in its own comment — peers absent from
  membership are **not** unregistered; the sync is additive only.
- `gossip_runtime.rs:314` — `register_peer` is a plain `self.peers.insert(...)`. A new
  key for an existing node **adds** an entry; it does not replace one, because the map
  is keyed by the 32-byte gossip id, not by the membership `node_id`.
- `gossip_runtime.rs:329-330` — `unregister_peer` keys solely on that id, and no-ops on
  a peer membership never names.

So for a node whose published key changes from W to G, W stays registered for the
lifetime of the daemon process, and a later revocation of that node removes only G.

**Severity, stated honestly rather than inflated.** In the specific case the alignment
increment creates, W is a WireGuard X25519 public key for which no Ed25519 private key
exists, so nothing can sign as W and the stale entry is inert. The defect is real for
the *general* rotation case — `MembershipOperation::RotateNodeKey` — where the old key
is a genuine gossip key whose private half does exist. That is a revocation gap, not a
theoretical one, and it is the reason this is filed before the increment rather than
after.

**The additive behaviour is DELIBERATE, and the obvious fix would regress it.**
`daemon.rs:5508-5512` gives the reason in full: *"an in-flight D2.7 enrollee is
consume-registered before its membership admit lands, and dropping it here would break
the enrollment bootstrap ordering. Absence is not revocation; explicit revocation is
what removes a peer."* So "compute the desired set and unregister the difference" —
the first fix anyone will reach for, and the one this entry originally proposed — would
drop every enrollee in the window between consume-registration and membership admit.
Recorded because that is the trap, not a footnote.

**Fix shape (not implemented, and needs its own design):** the gap is specifically a
*superseded key for a node membership still names* — which is distinguishable from
*a node membership does not name yet*. A sync that unregisters only ids belonging to a
node_id whose membership entry now carries a different key would close the rotation
gap without touching the enrollment window. That requires a node_id→gossip_id reverse
map the runtime does not currently keep, which is why this is a design item rather than
a one-line fix. A restart masks the gap, which is why it has not been noticed.

---

### QH-37 — RESOLVED `fdbdee18` — A logical CSV column merged its stages with `pass` outranking `skip`, so `linux_stage_cross_network=pass` had ALWAYS meant "2 of 11 ran"

**Verified against `cfb7a87e` by direct count, not inference.** Same class as QH-07 (the
`two_hop` alias contamination CLAUDE.md §12.3 warns about) — different column, still
live, and unlike QH-07 it is not fixed at the source.

`status_rank` (`crates/rustynet-cli/src/live_lab_run_matrix.rs:2145-2150`) ranks
`fail => 8`, `pass => 4`, `skip => 3`. When several stages share one logical column the
highest rank wins, so a single pass outranks any number of skips. `fail` correctly
dominates; `skip` does not.

Measured across the four most recent runs:

| Run | cross_network stages | ledger column |
| --- | --- | --- |
| `s0-probe-live-20260808` | pass 2 / skip 9 | **pass** |
| `gossip-producer-proof-20260808` | pass 0 / skip 11 | skip |
| `gossip-producer-proof2-20260808` | pass 2 / skip 9 | **pass** |
| `gossip-convergence-stage-20260809` | pass 2 / skip 9 | **pass** |

The only two that ever run are `cross_network_preflight` and
`cross_network_nat_classification`. The other nine need a second physical network.

**Why it matters more than it looks.** Every judgement about lab state reads this
ledger. A reader — including an agent writing a handover — sees `cross_network=pass`
and concludes the cross-network suite is green, when in practice 9 of 11 stages have
never executed in that run. This document's author made exactly that error in a report
on 2026-08-07 before catching it here.

**Fix shape (not implemented):** make `skip` dominate `pass` in a logical merge, the way
`fail` already does — a partially-skipped set must not read green. One function plus
tests, no lab run. Do this BEFORE adding roles to un-skip stages: the result of that
work is unreadable while the column can lie.

**Caution for whoever reads the history:** the fix changes how historical rows are
*interpreted*, not the stored data. The committed rows were NOT retro-edited; they are
evidence of what the tooling said at the time.

**RESOLVED in `fdbdee18`.** `skip` now outranks `pass`; `fail` still dominates both,
pinned by its own test. Blast radius measured BEFORE the change: **67 of 2944**
run×column pairs change interpretation — 44 `managed_dns`, 12 `anchor`, 9
`cross_network`, 1 `bootstrap`, 1 `exit_handoff`. Each was inspected and every one is a
genuine false green, not a newly introduced false red: the 44 `managed_dns` cases are
`distribute_dns_zone` **pass** + `live_managed_dns_validation` **skip**, i.e. the bundle
was distributed while the validation never ran. Statuses that never co-occur with `pass`
in a merged column (`not_run`, `reused`) were left alone — measured at 0 occurrences
each.

**The "latent sibling" this entry originally claimed was WRONG, and the correction is
the useful part.** It said `not_proven` — a node-scope fail that could not be attributed
to a specific node — was absent from `normalize_status`, fell to `unknown` (rank 2), and
would therefore also be masked by a `pass`. The first half is true; the conclusion is
not. **It cannot be masked, because it never reaches the merge.**
`attributable_node_status` (`live_lab_run_matrix.rs:794`) has exactly ONE production
caller, `write_node_stage_result_ledgers`, which writes the PER-NODE ledger — one row per
node×stage, nothing merges. Measured: **74** occurrences in
`live_lab_node_stage_results.csv`, **0** in `live_lab_node_run_matrix.csv`, and every run
containing one already carries `overall_result=fail`. No stage source emits it either —
0 hits across every `run_summary.json`.

That mistake is the same shape this register keeps recording: a correct narrow fact (the
word is missing from the vocabulary) driving a conclusion about behaviour, without
checking whether the value ever reaches the function.

**Hardened anyway in the follow-up commit**, because the guard is free and the measurement
proved it changes nothing on disk: `not_proven` is now recognised by `normalize_status`
and ranked WITH `fail`, so if a later change ever does route it into a merged column it
fails closed instead of degrading to `unknown` and being outranked by a pass. Pinned by
`not_proven_is_ranked_with_fail_and_survives_normalisation`, whose doc records that it
guards a currently-unreachable path.

---

### QH-38 — `spawn_with_timeout` lets the child inherit the test harness's stdout/stderr, so its tests are flagged LEAK under nextest — intermittently

**Observed 2026-08-10** in a full gate run at `cadbf631`:
`Summary [78.189s] 10461 tests run: 10461 passed (1 leaky), 2 skipped`, the leaky one
being
`LEAK [0.713s] rustynet-cli::bin/rustynet-cli vm_lab::overnight::executor::tests::spawn_with_timeout_returns_exit_status_for_a_fast_command`.
The two immediately preceding full runs (10453 and 10459 tests) reported **no** leaky
test on the same machine, so it is **intermittent**, not deterministic.

**Verified mechanism.** `spawn_with_timeout`
(`crates/rustynet-cli/src/vm_lab/overnight/executor.rs:607-618`) sets
`.process_group(0)` and does **not** redirect stdio, so the child inherits the test
binary's stdout/stderr. Its sibling `spawn_capture_with_timeout` (`:647-655`) does the
opposite — `.stdout(Stdio::piped())` / `.stderr(Stdio::piped())` — and is not implicated.
The poll loop sleeps 500 ms between `try_wait` calls (`:641`), which is consistent with
the measured 0.713 s for a command (`true`) that exits in about a millisecond.

**Inference, labelled as such:** nextest flags LEAK when a descendant still holds the
test's stdout/stderr after the test returns. Inherited stdio plus an own process group is
the shape that produces that, and the run duration says the loop took at least one 500 ms
nap before observing the exit. I did not instrument nextest to confirm the exact trigger.

**Why it is worth more than a warning.** The test PASSED, and one leaky test is not a
failure. But this repo runs ~10.4k tests as a process per test under one global
concurrency pool, and a leaked child holding an inherited pipe is precisely the shape
that produces order-dependent flakiness — the class CLAUDE.md §7 already records
(`mixed_platform_repo_sync_scripts_do_not_cross_dispatch` failing only under load, green
in isolation under both runners). An intermittent LEAK today is a flaky suite later.

**Affected tests:** `:982` (`…fast_command`) and `:990`
(`zero_timeout_waits_for_completion`) both spawn `true` through the un-piped path; `:971`
spawns `sleep 30` and exercises the kill path. Production callers are `:810`
(un-piped, same shape) and `:447` (the piped variant, unaffected).

**Fix shape (not implemented):** give `spawn_with_timeout` the same
`Stdio::piped()`/`Stdio::null()` treatment its capture sibling already has, so no child
inherits the harness pipes. Check first whether any production caller *relies* on the
child writing to the parent's console — `:810` is the one to read — because piping would
silence it, and that is a behaviour change rather than pure hygiene.

---

### QH-39 — two macOS baseline checks return `overall_ok: true` on a host with NO daemon running, and that green reaches the ledger

**Severity: HIGH (mesh-status) / medium (DNS). Confidence: VERIFIED — both reproduced live
on `macos-utm-1` 2026-08-11 with `pgrep rustynetd` finding no process.**

> **FRAMING CORRECTED 2026-08-11, same day as filing.** This entry originally said "two of
> them assert nothing". **That is true of `mesh-status` and FALSE of the DNS check**, which
> does real work: `evaluate_macos_dns_failclosed` (`macos_dns_failclosed.rs:41-58`) requires
> **every** nameserver to be loopback, so a public resolver in `resolv.conf` genuinely fails
> it, as do a missing file (`:67-73`) and an empty nameserver list (`:74-80`). Lumping the
> two together overstated the DNS half and would have pointed an implementer at the wrong
> fix. They are different defects with different severities and different remedies; the
> corrected descriptions are below. The original claim is left visible rather than deleted,
> per this register's own norm on retracted findings.

`validate_baseline_runtime` runs six `DaemonProbeOp`s that map to `macos-*-check`
subcommands (`vm_lab/mod.rs:11420-11432`). Two of them return green on a host with no
daemon, for two DIFFERENT reasons:

- **`macos-dns-failclosed-check` — a DEAD ASSERTION and a lying report field, not a
  content-free check.** `collect_macos_dns_failclosed_snapshot` sets
  `loopback_resolver_advertised` **hardcoded `true`** whenever the file reads
  (`macos_dns_failclosed.rs:117-138`), never deriving it from the parsed nameservers. That
  makes the drift branch consuming it (`:81-86`) unreachable **from the collector** — the
  `Err` arm that sets the flag false also sets `resolv_conf_present` false, which
  early-returns at `:72` before ever reaching `:81` — and publishes a field into the
  evidence JSON that is not derived from anything observed. **Not dead *code*:** the struct
  derives `Deserialize` and two unit tests (`:270-288`, `:407-430`) exercise the branch
  directly, so every coverage tool reports it as covered. A dead *assertion* that looks
  covered is harder to find than dead code, which is the point. The leak check at `:87` still works, so this is not
  "passes when a leak exists". The genuine gap is narrower and worth stating exactly: the
  check verifies `resolv.conf` **posture** and nothing verifies a resolver is actually
  **listening** on loopback — which is why it returned
  `{"overall_ok": true, "nameservers": ["127.0.0.1"], "loopback_resolver_advertised": true,
  "drift_reasons": []}` against a daemon-less host.
- **`mesh-status`** is invoked with only `--no-fail-on-drift` — no `--expected-peer-ids`,
  no `--max-age-seconds`. The `Ok` branch then performs **zero assertions**
  (`windows_mesh_status.rs:162-186`), so `overall_ok: true` means "a state file exists and
  parses". `macos-utm-1` recorded `MeshStatus: passed` while reaching no peer at all.

**Why it matters beyond the two checks.** Both greens propagate into
`macos_stage_baseline_runtime = pass` in the `--node` ledger. Run
`percontrol-rebaseline-20260811` carries that value for a node whose daemon was mid-restart
and whose network was partitioned from every peer. Any parity claim resting on
`macos_stage_baseline_runtime` is therefore unearned, and the column cannot be used as
evidence until this is fixed.

This is the MeshStatus-without-expected-peer-id false-green resurfacing; it has been
recorded before and is now measured on the `--node` engine.

**Acceptance, per check — they do not share one.**

> **The prescriptions below are REVISION 2.** Revision 1's two criteria were reviewed and
> both were wrong — in opposite directions. They are replaced, not amended, and the reasons
> are recorded because this register has already had to strike one false retraction (QH-07).

- **DNS.** Revision 1 said "derive `loopback_resolver_advertised` from the parsed
  nameservers". **That is a tautology and must not be implemented.** If every nameserver is
  loopback the derived flag is true and `:81-86` never fires; if any is not, `:87` already
  emits a reason. Under either `.all()` or `.any()` the branch can never independently
  change a verdict — the "fix" would leave the assertion exactly as dead while looking
  repaired. The only derivations that carry new information come from an **independent**
  source: `scutil --dns` (macOS's actual resolver configuration), or probing that something
  answers on loopback:53. Either that, or **delete the field and its branch** as the
  redundancy they are. Deleting is honest; deriving from the same data is not.
- **mesh-status.** Revision 1 said the fix "is not a small change" because
  `build_argv(op, daemon_path)` (`vm_lab/mod.rs:11338`) cannot carry peer ids. The
  signature claim is true and the conclusion is **wrong**: the plumbing already exists at
  both ends and only `build_argv` is narrow.
  - Daemon side: `macos-mesh-status-check` **already accepts** `--state-path`,
    `--expected-peer-id` (singular, repeatable) and `--max-age-seconds`
    (`rustynetd/src/main.rs:1758-1784`), threaded through `MacosMeshStatusOptions` into the
    evaluator.
  - Orchestrator side: `MeshStatusOverrides` (`vm_lab/mod.rs:26433-26441`) and
    `build_linux_mesh_status_extra_args` (`:26308-26323`) **already emit those flags**,
    exposed as `--mesh-status-expected-peer-ids` (`rustynet-cli/src/main.rs:4589`).

  So this is a **plumbing job** — give the `--node` probe path access to the same overrides
  the other path already uses — not a design job. Revision 1 would have sent an implementer
  to design a mechanism that exists.

  **The deflection to the dedicated stage does not hold either.** `mesh_status_validation`'s
  validator (`role_validation/mesh_status.rs:41-54`) also passes no peer ids and no max-age,
  so it carries the identical vacuous-`Ok` defect; it adds only an identity challenge on the
  node's own id. And it **skipped on macOS in the very run that motivated this entry**.

**The entry is not closed by the DNS half alone.** Its title is about checks that go green
on a host with no daemon; only the mesh-status fix addresses that. Prove each with the
negative case FIRST — make the check fail before trusting any green.

**ATTEMPT 1 (`744be8bb`) WAS REVERTED (`609ae2e7`). Read this before trying again.**

It did two things: armed `--max-age-seconds 120` on all three mesh-status checks, and removed
`DaemonProbeOp::MeshStatus` from the baseline probe set. Adversarial review found two
blockers, both verified against the code afterwards. **All gates were green — fmt, clippy,
10,535 tests — and caught neither.**

1. **The freshness bound is armed against a snapshot that is not periodically rewritten.**
   `persist_state` (`daemon.rs:9126`, called at `:9472`) sits INSIDE an apply block gated on
   `FailClosed || Recoverable || assignment_changed || membership_changed ||
   local_route_reconcile_pending` (`daemon.rs:9298-9304`). On a quiescent healthy node none
   of the five holds, the block is skipped, and the snapshot's age grows without bound.
   The reconcile loop ticks every second; **apply does not**, and the commit's "therefore"
   was a non-sequitur. It looked right because in a continuous run the
   `enforce_baseline_runtime` → `mesh_status_validation` window is 10–19 s (measured across
   all 12 runs carrying both). But the documented fast-iteration loop —
   `--skip-setup` / `--rerun-stage` against a reused setup dir, 12–25 min/iter
   (`LiveLabExecutionEfficiencyPlan_2026-06-20.md:35`) — would fail **healthy** nodes by
   6–12x. A false red is no better than the false green it replaced.
2. **Removing the probe loses mesh coverage on two paths.** `mesh_status_validation` depends
   on `KeyCustodyValidation` (`stage/mesh_status_validation.rs:36`), which **skipped in the
   cascade of the very run that motivated this entry** — so the stage made sole authority
   did not run, while the probe deleted for being redundant did. Separately it is
   `@ Live` while `validate_baseline_runtime` is `@ Setup` (`stage/mod.rs:149`, `:159`), so
   `--skip-linux-live-suite` — the documented mac/win inner loop — drops it from the plan
   entirely, leaving **zero** mesh coverage and not even a reported-skip artifact.

Two further findings, both making the removal worse than neutral:

- **The stated justification was factually wrong.** The commit claimed the baseline path
  "never deserializes, so no evaluator-side guard can ever reach it". The evaluator runs on
  the **guest daemon** and collapses to `overall_ok` (`windows_mesh_status.rs:126-129`),
  which the substring match reads. A bound passed to that probe **would** have taken effect
  — which is exactly what REVISION 2 above prescribed and the commit contradicted.
- **It was fail-open.** The probe was not assertion-free: the `Missing`,
  `IntegrityMismatch` and `InvalidFormat` arms push drift reasons **unconditionally**,
  outside the `if let Some(max_age)` gate (`windows_mesh_status.rs:148-158`). A node whose
  state file was wiped, unreadable or tampered previously FAILED the baseline stage and
  would now PASS it.

**And the tests did not discriminate what mattered.** They asserted the argv's shape, so a
semantically useless bound (`86400`) passes them, and nothing binds the orchestrator's flag
string to the daemon's parser — the two live in different crates with no shared pin.

**For the next attempt — resolve the scope question FIRST.** Freshness is not a sound
liveness signal here because the snapshot is change-driven, and daemon liveness is already
proven on the dedicated path by the §4.7 identity challenge. So the honest question is what
mesh-status *can* assert: today it genuinely asserts the snapshot exists, verifies its
integrity digest and parses — and `peer_ids` cannot be asserted against node ids (CIDRs, see
REVISION 2). It may be that the correct outcome is **not to manufacture an assertion at all**
but to stop over-reading its green, i.e. to fix how `macos_stage_baseline_runtime` is
interpreted rather than what the probe does. Decide that before writing code. If a bound is
used, justify it against the reuse loops, not only against continuous runs.

**Two things this entry did not record, both larger than the flag.**

1. **macOS declares `/etc/resolv.conf` non-authoritative.** The file itself states it "is not
   consulted for DNS hostname resolution … by most processes on this system", and the module
   doc concedes the point and defers `scutil --dns` to "a future slice"
   (`macos_dns_failclosed.rs:10-13`). So a green macOS DNS check attests the posture of a
   file macOS says is mostly not used. That is a scope problem, not a flag problem, and it
   subsumes the whole DNS item above.
2. **`validate_baseline_runtime` accepts any probe on a raw substring match** for
   `"overall_ok": true` (`adapter/ssh.rs:584-589`) — no schema-version check, no
   drift-consistency check, unlike the typed evaluators the dedicated stages use. Every one
   of its six probes inherits that weakness, not just these two.

### QH-40 — launchd SIGTERMs the privileged helper BEFORE the daemon, so every macOS rollback path fails while the process still exits 0

**Severity: HIGH (fail-closed). Confidence: VERIFIED from the guest's unified log,
run `percontrol-rebaseline-20260811`.**

On a plist reload, launchd signalled `com.rustynet.privileged-helper` (pid 16607) at
`01:01:18.984` guest-local and `com.rustynet.daemon` (pid 16611) at `01:01:18.985` — the
helper **one millisecond earlier**. The daemon's shutdown rollback then ran with no helper
to talk to, and logged:

> `rollback dns protection: rollback failed: firewall apply failed: … privileged helper
> response read failed: truncated frame header` … `backend shutdown: … privileged helper
> connect failed (…rustynetd-privileged.sock): Connection refused (os error 61)` …
> `exit-mode rollback failed` … `cleanup failed` … `interface cleanup failed`

Every teardown path failed — DNS protection, firewall, exit-mode, interface cleanup — and
launchd still recorded `exited due to exit(0)`.

**Why this is the most serious item from that run.** §4 requires fail-closed behaviour and
§10.7 treats exit-NAT residue as a release blocker. Here the residue is invisible: no stage
observed it, the daemon reported clean exit, and the run matrix shows nothing. A macOS node
that reloads its plist can therefore leave firewall and DNS state behind with no signal
anywhere.

**Open questions, not yet investigated:** whether the ordering is fixed or racy; whether
the helper should outlive the daemon by design (it plainly must, if the daemon needs it to
roll back); and whether the daemon should refuse to report exit(0) when rollback failed.
That last one is the fail-closed question and should be answered first.

### QH-41 — `macos-utm-1` is on an isolated vmnet bridge, so every mixed-OS run fails its traffic matrix deterministically

**Severity: medium (lab configuration, not product). Confidence: VERIFIED — measured
bidirectionally 2026-08-11 with no daemon running and no rustynet PF rules loaded.**

The host has two bridges: `bridge100` = 192.168.64.1 (members `vmenet0`, `vmenet1`) and
`bridge101` = 192.168.65.1 (member `vmenet2`, flags include **PRIVATE**). `macos-utm-1`'s
`en0` sits on the private bridge at 192.168.65.101; its second NIC `en1` is `status:
inactive`, `media: none`, DHCP `INACTIVE`. Both Debian guests are on `bridge100`.

Measured: mac → `192.168.64.4` and `.10` 100% loss, mac → its own gateway `192.168.65.1`
0% loss; debian-2 → `192.168.65.101` 100% loss, debian-2 → `192.168.64.1` 0% loss. With
`pfctl -s rules` showing only `com.apple` anchors and `pfctl -a com.rustynet -s rules`
empty, so nothing Rustynet did causes it.

The inventory records `live_ips: ["192.168.65.101", "192.168.64.18", …]` — the guest used
to be on the shared network, so this is drift, not a permanent property.

> **CORRECTED 2026-08-12 — the "drift" claim above is WRONG, and it is my error.** Measured
> with `plutil -p` on each `config.plist`: `macOS.utm` is `Mode = "Shared"`, `Backend =
> "Apple"`; every Linux guest is `Mode = "Shared"`, `Backend = "QEMU"`. **Both sides are
> already on "Shared".** UTM's Apple-Virtualization and QEMU backends each get their OWN vmnet
> shared network, so "Shared" names two different L2 segments depending on backend. The repair
> prescribed below — "put the guest back on the shared adapter" — is therefore a **no-op**, and
> a reviewer reasoning from this entry reached a wrong conclusion because of it. The split is a
> backend property; no mode change and no boot-order care merges the two bridges.

**Consequence:** `traffic_test_matrix` fails on every mixed-OS run, taking the rest of the
Linux suite with it, and no cross-OS stage can pass. This is the immediate blocker on
mixed-OS coverage, and it is separate from QH-39/QH-40.

**Note the boot-order interaction:** whichever backend starts first takes 192.168.64.x, so
boot order alone can move a guest between bridges and make inventory addresses look stale.
Fix (SUPERSEDED — see the correction above; kept for the record) by putting the guest back on
the shared adapter, then re-verify with a bidirectional
ping before spending run time.

### QH-42 — the network-evidence artifact rendered a verdict over a silently truncated finding set

**Severity: medium. Confidence: VERIFIED — reproduced on the live fleet and fixed
2026-08-11 (`9dd878ca`, corrected by `6cb4a8b5` and `a14c5227`).**

Split out of QH-41, which is a *different* defect (the vmnet bridge split). The two were
conflated while investigating that entry.

**Mechanism.** The network audit runs on every orchestrate launch
(`orchestrator/native.rs:1023`, from `:147` and `mod.rs:11990`) with `skip_guests: true`
(`:1031`). Every guest is then stamped `"skipped"`, and `detect_offfleet_subnet_findings`
drops any guest that is not `collected` (`network_audit.rs:884-885`) — so the off-fleet / L2
finding class **cannot fire**. The run still rendered a verdict and wrote it into
`orchestration/vm_network_evidence.json`, attached to the ledger row. Measured across all 16
orchestrate evidence artifacts on disk: **0/11 guests collected on 16/16**, and the artifact
disclosed nothing about it. A reader saw network evidence attached to a run and reasonably
concluded the underlay had been checked.

**Fix: disclose, do not gate.** The artifact now carries `guest_observation`
(`collected`/`skipped`) and, when skipped, an `evidence_limitations` entry naming the
unevaluated class.

**What was tried and reverted, because it is the obvious move and will be tried again.**
Downgrading `overall_status` to `not_run` on a truncated run makes two wired operator paths
**permanently unsatisfiable**: three callers hardcode `--skip-guests`
(`rustynet-mcp/src/bin/lab_state.rs:5582`, `:5738`, `:6023`) and the orchestrate gate stops a
run on ANY non-`pass` status, not just `fail` (`native.rs:1064-1068`). The moment the
inventory's stale labels are repaired — the repair this register recommends — a healthy fleet
would fail `ensure_lab_ready(profile=…)` with nothing left to fix and no way to clear it. The
reason is recorded on `overall_status_from_findings` itself.

**Also worth knowing before trusting `off_fleet_subnet` for anything.** Its "fleet management
plane" is chosen by vote among `network_group` labels, currently a **4–4 tie** broken by
comparing CIDR *strings* (`network_audit.rs:873-876`) — so `192.168.121.0/24` wins only
because `'1' < '6'`. Three of the voting labels are ones the same audit reports as
`stale_network_group`. Repairing them **inverts the entire finding set**. The tie-break and
the stale labels both need dealing with before that finding gates anything.

**Not fixed here:** flipping `skip_guests` so the class can actually fire. The audit runs
before readiness — before guests are powered on and before live IPs are refreshed — so it
would record healthy guests as unreachable, arm an unbounded SSH before shutdown handlers and
stage deadlines exist, turn `--dry-run` into a live fleet sweep, and authenticate with the
operator's `~/.ssh/known_hosts` rather than the run's. If live observation is wanted it
belongs **after** readiness, as a stage, scoped to the elected nodes.

### QH-43 — three cross-OS columns reported a host→guest push under names promising guest↔guest reachability

**Severity: HIGH (evidence integrity). Confidence: VERIFIED — measured, fixed 2026-08-12.**

Third instance of the class QH-07 and QH-37 belong to: a column whose *name* promises a
property its *feeder* does not measure.

**Measured before the fix.** `cross_os_direct_path` read **`pass` on 10 rows**, fed by exactly
one stage — `distribute_traversal`, a Bootstrap-group host→guest SSH push. On **9 of those same
rows** `cross_os_peer_visibility` — the only cross-OS column fed by a real reachability
validator — read `fail`. `cross_os_direct_path`, `cross_os_dns` and
`cross_os_membership_convergence` had **byte-identical 107-value vectors**, because
`cross_os_dns`'s three "real" validators are all `state_machine_only: false` (bash-dialect
names the `--node` engine never emits), so the push was the only thing that ever wrote it.

The mechanism: the orchestrator host owns **every** lab bridge, so a host→guest push succeeds
across a total guest-to-guest severance. `distribute_traversal` cannot fail for the reason its
column name implies. Independently corroborated by QH-41's bidirectional measurement.

**Fix.** The four distribution stages (`distribute_traversal`, `distribute_dns_zone`,
`membership_init`, `distribute_membership`) no longer feed any cross-OS column, at the registry
AND at `oracle_cross_os_column` in lockstep — the latter is pinned by a named CI gate
(`scripts/ci/orchestrator_engine_gates.sh:59`), which the plan initially claimed could not
break. Guarded by three tests asserting against the **registry spec**, because QH-07's own
commit warns that editing both sides at once leaves every equivalence test green.

**The guard's axis is the direction of the proof, not the stage group.** A group-based rule
flags SIX stages, and the two extras — `validate_macos_mesh_join`, `validate_windows_mesh_join`
— are Bootstrap-group validators that legitimately measure guest-side state and feed the one
column that works. A blunter rule would have broken it.

**FORWARD-ONLY.** The 10 historical `pass` values in each of the three columns stay wrong.
Do not read any pre-2026-08-12 row of `cross_os_direct_path`, `cross_os_dns` or
`cross_os_membership_convergence` as evidence of anything.

**Two columns are now deliberately unfed** — `cross_os_direct_path` and
`cross_os_membership_convergence` read `not_run`, which is the truth. They are owed a real
validator: a guest↔guest reachability probe and a membership-convergence assertion read from
the guests. **Both are blocked on QH-41** — the vmnet backend split means no cross-OS
reachability validator can pass in this lab until it is resolved.

**Known cost, accepted:** `find_untested_work` (`rustynet-mcp/src/bin/lab_state.rs:2323-2414`)
classifies unfed columns as never-run and emits them as suggested lab targets, so these two
become permanently unsatisfiable suggestions until a validator exists.
`cross_os_anchor_enrollment` is the pre-existing instance — zero feeders, `not_run` on 107/107.

## Related documents

- `NodeEngineFlipDispositions_2026-07-24.md` — D1 carries the two_hop mechanism,
  the atomicity exposure behind QH-04, and the evidence-integrity note in QH-09.
- `TraversalSelfSustenancePlan_2026-07-23.md` — cross-referenced by QH-04.
- `HostObservabilityStabilityPlan_2026-07-24.md` — §7.10 names the confused-deputy
  threat model that QH-01 and QH-02 sit inside.
- `LinuxVmHostPlan_2026-07-14.md` — the remote-host lab work that surfaced QH-10.
- `CLAUDE.md` / `AGENTS.md` §3, §4, §7, §10.2, §10.4, §10.6 — the constraints
  these items enforce.

### QH-44 — four of five lab guests silently lost their SSH `authorized_keys`

**Status: OPEN, diagnosed only as far as ruling causes out.**

Across one session (2026-08-13) four of the five reachable UTM guests failed the
orchestrator's readiness gate with the identical signature — TCP/22 open, publickey
rejected:

```
<alias> ready process_present=true live_ip=<ip> ssh_port_status=open ssh_auth_status=failed-exit-255
```

`macos-utm-1`, `fedora-utm-1`, `rocky-utm-1` and `ubuntu-utm-1` each needed the key
re-primed from the untracked secrets sidecar before any run could start. Only
`debian-headless-2` / `-4` were unaffected. Each recovery cost a failed run plus a
guest restart, so this is the single largest source of wasted lab wall-clock in that
session.

**Ruled out so far:**

- **Not the orchestrator's teardown.** `cleanup_runtime_state` removes only
  `/etc/rustynet`, `/var/lib/rustynet`, `/run/rustynet*`
  (`adapter/linux_install.rs:358`); nothing under it touches `~/.ssh`. A repo-wide
  grep for `authorized_keys` in lab code finds only the Windows access-bootstrap
  helper and cloud-init seed templates.
- **Not cloud-init re-seeding.** `ubuntu-utm-1` reports `cloud-init` as `not-found`
  with no unit installed, yet it had still lost its key.

**Not yet established:** whether the guests are being restored from a snapshot, were
provisioned before the current key existed, or something else removes the file. The
readiness gate reports the symptom correctly and fails closed, which is right — the
gap is that nothing records WHEN the key disappeared, so the window cannot be
correlated with a run.

**Why it matters beyond convenience:** the readiness gate's restart-and-retry cannot
fix an auth failure, so the run aborts after a full VM restart cycle. A guest that
loses its key is effectively out of the fleet until a human primes it, which silently
shrinks every topology and is indistinguishable, in the run matrix, from a guest that
was never selected.

**Suggested first step:** record `~/.ssh/authorized_keys` mtime and a hash in the
discovery summary, so the next occurrence carries a timestamp to correlate against.

### QH-45 — the `entry` role emits an nft rule the privileged helper's allowlist rejects

**Status: OPEN, fully diagnosed. The fix is SECURITY-SENSITIVE and must not be a quick widen.**

First seen in `enroll-diag-20260813r`, the first run in which `live_two_hop_validation` ever
executed (it needs an `entry` node, which no prior topology elected).

Chain, measured end to end:

```
live_two_hop_validation fail
  → root command failed for fedora@192.168.64.103:22 with status 65 (EX_DATAERR)
  → last step reached: "[two-hop] advertising default route on final exit and entry relay"
  → fedora rustynetd: restrict_recoverable: reconcile dataplane apply failed:
      firewall apply failed: i/o failed: unsupported nft add rule argument schema
  → systemctl is-active rustynetd → inactive
```

**The helper is behaving correctly.** `privileged_helper.rs:1954` is an explicit allowlist: every
`nft add rule` argv is matched against known-good schemas and anything unmatched is refused. That
is the §4 privileged-boundary control (argv-only exec, strict input validation) working as
designed. The daemon then fails closed and stops, which is also correct.

The defect is that the `entry` role's dataplane emits a rule shape the allowlist does not carry.

**Why the obvious fix is wrong.** Widening the allowlist to accept whatever `entry` emits would
relax a privileged-boundary control to make a test pass — the definition of a happy-pass edit on
the most security-sensitive surface in the daemon. The allowlist entries are deliberately
narrow (the DNS-redirect arm, for example, pins a fixed daddr, a fixed dport, matching l4proto
and a local-only redirect target).

**What the fix must establish first, in this order:**

1. **Which exact argv is rejected.** Not yet captured — the helper logs the refusal but the run
   evidence does not carry the offending argument vector. Capturing it is step one, and is itself
   an evidence gap worth closing.
2. **Whether that rule is legitimate for `entry` at all.** An entry/relay hop forwarding for
   peers may need a shape no other role needs — or may be emitting something it should not.
3. **Only then**, if legitimate, a new allowlist arm as narrowly bounded as its siblings, with
   the same style of pinned literals, plus a negative test proving a near-miss is still refused.

**Not reproducible without an `entry` node.** Fedora has passed as `relay` in prior runs; it is
the `entry` role's rule path that trips this, which is why it stayed hidden until a five-node
topology could elect one.

### QH-48 — the live suite is a linear dependency chain, so each run surfaces at most one defect

**Severity: medium (throughput, not correctness).** Nothing here is wrong in a released binary; it
governs how fast defects can be found.

Measured on run `qh46-snat-20260813x` (33 passed / 1 failed / 24 skipped): **21 of the 24 skips
descend from the single `live_two_hop_validation` failure.** Only four are genuine topology gaps
(`blind_exit` x2, `anchor_validation`, `admin_issue` — no node in the topology holds those roles).

The declared dependencies form a strictly linear chain, each stage naming exactly its predecessor:

```
live_two_hop_validation
  -> live_managed_dns_validation -> live_network_flap_validation
  -> live_reboot_recovery_validation -> live_secrets_not_in_logs_validation
  -> live_key_custody_validation -> live_enrollment_restart_validation
  -> live_lan_toggle_validation -> live_mixed_topology_validation
  -> live_anchor + 10 x cross_network_*
```

`is_blocking` is `Failed | NotRun` and the runner propagates `blocked` transitively, so one failure
blocks every descendant. That is the designed behaviour, not a bug in the runner.

**Why it is still worth changing.** Some links are genuine data dependencies — `live_managed_dns_validation`
does validate against the multi-hop topology that `live_two_hop_validation` establishes. Most are
not: `live_key_custody_validation` does not require that secrets were absent from logs, and
`live_lan_toggle_validation` does not require an enrollment restart. Those pairs encode *ordering* as
*gating*. The cost is that a ~17-minute run yields at most one new defect, so N defects need N runs.

**A correction to an earlier framing in this ledger:** the cross-network stages were previously
described as skipped for want of a cross-network substrate. On this run they were skipped by the
cascade and never attempted, so their substrate requirement is untested, not confirmed.

**Fix direction (needs plan + adversarial review before any code):** separate "runs after" from
"requires the predecessor to have passed". Destructive stages — reboot recovery, network flap —
plausibly need serialising against each other, and that ordering must survive; what should not
survive is an unrelated stage being gated on an unrelated predecessor's verdict. Correct the
individual declarations to reflect true data dependencies rather than deleting gating wholesale: a
stage that genuinely needs prior state must keep its gate, or it will produce confident garbage on a
broken mesh. Do not treat converting a skip into a run as progress in itself — the value is more
real verdicts per run, and some newly unblocked stages will legitimately fail.

### QH-49 — the LAN-toggle stage hardcodes the SSH username, so it cannot drive a non-Debian guest

**Severity: medium. FIXED (fix landed with this entry); it had never been exercised before.**

`live_lan_toggle_validation` drives three guests — exit, client, and an aux/extra/entry node it
promotes to the blind-exit posture. Both helpers that resolve those targets took the HOST from the
node's own adapter but supplied a HARDCODED username:

```rust
// alias_matching_label — used for exit AND client
let user = match adapter.platform() {
    VmGuestPlatform::Windows => "admin",
    _ => "debian",
};
// find_blind_exit
user: "debian".to_owned(),
```

`SshConnectionParams` carries the real `user: Option<String>` from the inventory, and it was
discarded in both places. On an all-Debian topology the hardcoded value happens to be right, which is
why this survived: the defect only appears once a non-Debian guest lands in one of those three roles.

**Measured on run `qh46-series-20260813z`** (38 passed / 1 failed / 20 skipped), where this was the
only failing stage:

```
remote command failed on debian@192.168.64.103:22:
  debian@192.168.64.103: Permission denied (publickey,gssapi-keyex,gssapi-with-mic,password)
```

`192.168.64.103` is `fedora-utm-1`. The inventory recorded `ssh_user=fedora` correctly the whole
time — so this was one node's username dialled against another node's address.

**Fix:** a single `resolve_ssh_user(inventory_user, platform)` used by both helpers, preferring the
inventory value and trimming it, with the previous hardcoded values retained ONLY as the
absent/blank fallback. The fallback deliberately does not adopt the `root`/`admin`/`administrator`
triple that the sibling `ssh_params_for_role` uses in `chaos.rs` / `cross_network.rs`: changing an
untested fallback is a different change from fixing "the real username was available and thrown
away", and bundling them would make any regression here impossible to attribute. That divergence
between the two families of helper is worth reconciling separately.

**Note on how it surfaced.** This stage only ran because `live_two_hop_validation` SKIPPED rather
than failed on that run, letting the dependency chain continue — the effect QH-48 predicts. It also
produced a zero-byte `live_lan_toggle.log`: the stage's binary-output capture worked, the binary
simply wrote nothing before dying, so the whole diagnosis came from the failure digest's
`condensed_result`.

### QH-47 — NAT rules are applied without ever flushing conntrack

**Severity: medium.** Not lab-only; it affects any node that gains or changes an exit/relay role
while traffic is already flowing.

`nftables` nat chains are traversed only for the first packet of a flow. Once conntrack confirms a
flow, its NAT binding (or absence of one) is fixed, and later packets never re-enter the nat hook.
The dataplane recreates its nat table per generation — the table name carries a generation suffix,
e.g. `rustynet_nat_g2` — and deletes the previous one, but **nothing flushes conntrack anywhere in
the daemon**. Searching `crates/rustynetd/src/` for `conntrack` returns three matches, all of them
`ct state established,related accept` rules; none is a flush.

Consequence: a flow established before a masquerade rule is installed is never masqueraded, for as
long as conntrack keeps the entry alive. Because an entry is refreshed by each packet, a steady
traffic stream keeps a stale, un-NATed binding alive indefinitely rather than ageing it out.

This also changes how the rule counters must be read when diagnosing. The forward chain is ordered
`ct state established,related accept` first, so both the hairpin forward counter and the nat chain
observe only NEW-state packets. A non-zero forward counter alongside a zero nat counter is therefore
consistent with the nat table having been created after those packets flowed, and is not by itself
evidence that the nat rule is malformed.

**Fix direction (not yet implemented):** flush the affected conntrack entries after a NAT change, at
minimum those for the tunnel subnet. Any such flush must go through the privileged-helper allowlist
as an argv-only invocation with validated arguments (§4); it must not be built by string
construction, and it is not a weakening of the allowlist to add a narrowly shaped entry for it.
Whether this is QH-46's cause is a separate question, tracked there.

### QH-50 — blind_exit NAT scan could not pass on a firewalld host, and missed a real NAT rule

**Severity: high (release-blocking on RHEL-family). FIXED and mutation-proven.** Found while designing
the [[QH-46]] fix; independent of it.

`evaluate_linux_blind_exit_ruleset` scans the host ruleset and must find no NAT, because a blind exit
never rewrites the mesh source. It looked for the substrings `"masquerade"`, `" snat "` and
`" dnat "`. That was wrong in BOTH directions on a real host:

* **False positive.** nftables uses `dnat`/`snat` as conntrack status FLAGS as well as NAT
  STATEMENTS. `ct status dnat accept` tests whether some other party translated a flow and translates
  nothing itself. Stock firewalld ships three such lines in `filter_FORWARD` — measured on
  `fedora-utm-1` while diagnosing QH-46 — so `rustynetd linux-blind-exit-dataplane-check` could not
  be satisfied on ANY firewalld host, failing for a reason unrelated to NAT.
* **False negative.** The space-delimited substrings could never match a keyword in the FIRST token,
  because `normalize_nft_rule` strips indentation. An unconditional `dnat to 10.0.0.1` rule passed a
  control whose entire purpose is to reject it.

**Fix:** recognise a NAT statement structurally — `masquerade` as a bare token, or `snat`/`dnat`
followed by `to`, optionally through a family qualifier (`dnat ip to ...`). Requiring the `to` keeps a
chain merely NAMED `dnat` from tripping the control, and is also what makes the conntrack matches
safe without any pre-stripping pass.

**Divergence from the reviewed plan, deliberate.** The design review proposed fixing this by narrowing
the capture to Rustynet's own `inet rustynet_g*` table. That would remove the false positive by making
the control blind to FOREIGN NAT — and a firewalld zone with masquerading enabled rewrites this node's
egress exactly as effectively as one of our own rules would. Narrowing scope converts a true positive
into a fail-open on precisely the hosts most likely to carry one. The defect was in the MATCHER, not
the scope, so the scan stays host-wide.

**Verification.** Eight tests, three mutations:
* disabling the (initially written) `ct status` stripping pass changed NO verdict — all tests stayed
  green, proving that code was redundant, so it was removed rather than propped up with a test;
* removing the `to` requirement fails 3 tests (exit 101);
* restoring the original substring semantics fails 4 tests (exit 101), including the leading-token
  false negative.

**Follow-up not bundled here:** the scan does not recognise `redirect`, which is also NAT. Adding it
would strengthen the control beyond the defect being fixed, so it is recorded rather than smuggled in.

### QH-51 — network-flap recovery: the handshake never returns after the block is lifted

**Status: OPEN — 3 of 4 checks pass. TWO hypotheses now tested and REFUTED (2026-08-14).**

Refuted #1 — roaming churn destroying the record (run `qh51-roam-20260814h`).
Refuted #2 — the keepalive never reaching the tunnel (run `qh51-keepalive-applied-20260814i`):
`baseline=72 ok=true`, `disruption_confirmed=true`, `recovery_arrived=FALSE`.

Both fixes are correct independently and stay. Both predicted recovery. Neither produced it.

**STOP FIXING AND MEASURE.** Two consecutive falsified predictions mean the remaining cause is not
where code reading suggests, and a third guess is not worth its risk. The next step is a capture, not
a patch.

**The specific thing to suspect first, and why it was missed.** The stage reads
`traversal_probe_latest_handshake_unix`, which is populated from `traversal_probe_statuses` — the
TRAVERSAL PROBE's record, NOT the backend's handshake telemetry directly. So the metric only refreshes
when a probe actually runs. If probing is suppressed after the flap, handshakes could be resuming
perfectly well and this field would still never update. The journal shows the flap breaker driven to
`open` at intensity 0.97 for this peer on every affected run. `daemon.rs:6885` was checked and gates
only the QUALITY re-race — but `traversal_probe_due` was NOT checked, and it is the function that
decides whether a probe runs at all.

**Suspect ELIMINATED by reading, 2026-08-14:** `traversal_probe_due` (`daemon.rs`) contains NO
breaker consult. Probing is paced by `next_reprobe_unix` and by handshake freshness, and the flap
breaker gates only the quality re-race at `:6885`. So probes are NOT suppressed after the flap, and
the metric's failure to refresh is not a probe-scheduling problem. That removes the leading suspect
named above and leaves "no handshake is occurring, or it occurs and the backend records nothing" as
the live question.

**One INTERACTION worth checking first, created by this session's own fixes.** The keepalive is
applied only in `Tunn::new`, and the new `Unchanged` disposition deliberately stops rebuilding the
tunnel for an unchanged peer. On a fresh daemon start the peer is `Added` and therefore gets the
keepalive, so this should be benign — but it has NOT been verified on a live node, and if any path
configures a peer before its keepalive is known, that peer keeps a keepalive-less tunnel for the
lifetime of the process. Confirm on the client with `rustynet status` that the configured peer
actually carries a 25s keepalive before assuming the daemon is emitting them.

**Two MORE suspects eliminated by reading, 2026-08-14:**
* boringtun timers ARE pumped — `engine.rs:452` calls `Tunn::update_timers`, so keepalives and
  handshake retries do fire. Not a dormant-clock problem.
* The keepalive DOES reach the client's peer — `daemon.rs:13438` is the ONLY production `PeerConfig`
  construction site in the daemon (every other match is a test helper), and it sets `Some(25)`.

**Leading remaining hypothesis, UNVERIFIED — the metric is paced, not dead.** `traversal_probe_due`
returns `status.next_reprobe_unix.is_none_or(|next| now_unix >= next)` for a handshake that was
ALREADY stale at the previous evaluation — which is exactly the state after a 35s block. So the probe
is deliberately BACKED OFF, and the field the stage reads only refreshes when a probe runs. If the
back-off exceeds the stage's 180s recovery poll, the tunnel can genuinely recover while the metric
never refreshes inside the window. That would make this a measurement-window problem rather than a
recovery failure, and it is consistent with `tunnel_active=true` and `membership_intact=true` on
every failing run.

**How to settle it without changing the assertion:** capture `traversal_probe_next_reprobe_unix` and
`traversal_probe_attempts` on the client across the recovery poll. If `next_reprobe_unix` sits beyond
the poll window and `attempts` does not rise, the tunnel's recovery is simply not being sampled — and
the correct fix is to make the stage observe recovery through something that is not probe-paced (or
to force a reprobe), NOT to relax what counts as recovered.

**The capture that settles it** (run mid-stage; `final_cleanup` is `always_run`): on the client,
every 5s across the recovery poll, record `traversal_probe_result`, `traversal_probe_attempts`,
`traversal_probe_next_reprobe_unix`, and `traversal_probe_latest_handshake_unix` together in ONE
sample. Rising `attempts` with a stale timestamp means probes run but record nothing. Static
`attempts` with `next_reprobe_unix` in the past means probing is suppressed — look at
`traversal_probe_due` and the breaker. Do not compare values across runs, and do not read the
pass/fail from a ledger column.

**Do NOT widen the recovery assertion.** It is the only check proving the tunnel comes back.

I predicted the endpoint-rebuild churn was destroying the handshake record faster than it could be
written, and that fixing it would produce recovery. Run `qh51-roam-20260814h`, with that fix live:

```
baseline_handshake_age_s = 68           ok=true
mid_handshake_age_s      = unreadable   disruption_confirmed=true
recovery_arrived         = false        <-- prediction FALSIFIED
```

The roaming fix is correct on its own merits and stays (a WireGuard session is keyed by the static
keys, not the address; rebuilding a live tunnel because a peer moved is wrong regardless). But it was
NOT what blocked recovery. Record this as refuted so nobody re-runs the same reasoning.

**What is now established by elimination.** The record survives an unchanged reconcile (baseline is
readable, 68s) and survives roaming, yet after the block lifts NO handshake is recorded within the
180s poll. So the remaining question is no longer "what deletes the record" — it is **"why does no
handshake occur, or occur without being recorded, after the client's egress is restored"**.

Three candidates, in the order they are cheapest to test, none yet checked:
1. **The handshake is never initiated.** `initiate_handshake` is driven by the daemon; if nothing
   calls it for this peer after the block lifts, and no outbound traffic is generated during the
   poll, WireGuard has no reason to speak. The 25s persistent keepalive should defeat this — verify
   it actually reached the peer config on the live node (`wg`-equivalent state via `rustynet status`),
   because a keepalive that is set but not applied looks identical from here.
2. **The handshake occurs but is not recorded.** `record_authenticated_handshake` fires only when the
   engine returns `Some(observed)`; check whether the response-message path (as opposed to the
   initiation path) returns it.
3. **The flap breaker suppresses re-initiation.** It reaches `open` at intensity 0.97 for this peer.
   `daemon.rs:6885` gates only the quality re-race, but confirm no other consult point gates
   initiation.

**Do NOT widen the recovery assertion.** It is the only check proving the tunnel comes back; the
whole stage is worthless without it.; only recovery detection remains (2026-08-14).**

Progression across runs, each figure from the stage's own log:

| run | baseline | disruption_confirmed | recovery |
| --- | --- | --- | --- |
| `qh46-firewalld-20260814c` | `u64::MAX` (unreadable) | `pass` — on missing data | false |
| `qh51-measure-20260814e` | `unreadable` | `fail` — honest | false |
| `qh51-session-20260814f` | **`70` — READABLE** | false | false |
| `qh51-final-20260814g` | readable | **`true`** | **false** |

The baseline became readable the moment the session-rebuild fix landed, which is the direct evidence
that fix works: handshake telemetry now survives reconcile instead of being wiped every cycle.

**What remains, precisely.** After the block is lifted the handshake record never becomes readable
again within the 180s poll, while `tunnel_active=true` and `membership_intact=true`. The likely
mechanism, NOT yet confirmed: the post-disruption traversal re-race keeps supplying a NEW endpoint,
so `configure_peer` legitimately reports `Replaced` on each pass, rebuilds the session and clears the
record again — meaning the record is destroyed as fast as it is created. That is consistent with the
journal showing the flap breaker driven to `open` at intensity 0.97 for this peer.

**Do not "fix" this by widening the recovery check.** Recovery is the one assertion in this stage
that must stay strict: it is the only thing proving the tunnel actually comes back. The next step is
to determine whether the endpoint genuinely changes after unblock (making each rebuild correct, in
which case the churn itself is the defect) or whether the same endpoint is being re-applied through a
path that bypasses the `Unchanged` comparison — for example `update_peer_endpoint` rather than
`configure_peer`. Capture the client's `traversal_probe_endpoint` and
`traversal_probe_latest_handshake_unix` every 5s across the recovery window; a changing endpoint
proves the first, a constant one proves the second.

**Superseded status:**, daemon-side cause now isolated and unmasked.**

The instrument is fixed and the stage is now honest. Run `qh51-measure-20260814e`:

```
[network-flap] baseline_handshake_age_s=unreadable ok=false
[network-flap] mid_handshake_age_s=unreadable disruption_confirmed=false
checks.wg_disruption_confirmed = fail      <-- was `pass`, on missing data
```

That flip from `pass` to `fail` on identical tunnel behaviour is the proof the repair works: the
check no longer manufactures confirmation out of an unreadable metric. The stage still fails, but it
now fails for a true reason instead of passing for a false one.

**Daemon-side cause ISOLATED to the userspace backend's handshake telemetry (2026-08-14).** The call
chain, traced end to end:

```
netcheck path_latest_live_handshake_unix / traversal_probe_latest_handshake_unix
  <- daemon.rs:7344-7370   from self.traversal_probe_statuses[peer].latest_handshake_unix
  <- phase10.rs:111        controller.backend.peer_latest_handshake_unix(node_id)
  <- backend-userspace/lib.rs:160          delegates to LinuxUserspaceSharedBackend
  <- userspace_shared/mod.rs:496           control.peer_latest_handshake_unix(node_id)
  <- userspace_shared/runtime.rs:589       self.handshake_telemetry.latest_handshake(node_id)
```

Note the KERNEL backend reads this with `wg show <iface> latest-handshakes`
(`linux_command.rs:379-397`), which cannot inspect a userspace interface — so the userspace path
deliberately does NOT use it and keeps its own `HandshakeTelemetry` instead. That telemetry is
recorded at three sites in `runtime.rs` (`:656` on initiate, `:841`, and `:874` inside
`process_inbound_ciphertext`), so both directions are covered in principle, and each records only
when the engine returns `Some(observed_handshake)`.

**MECHANISM IDENTIFIED 2026-08-14 — session churn on reconcile wipes the handshake record.**

`runtime.rs:560-566` clears the telemetry whenever the engine reports `Replaced`:

```rust
let disposition = self.engine.configure_peer(&peer)?;
if matches!(disposition, ConfigurePeerDisposition::Replaced) {
    self.handshake_telemetry.clear_peer(&node_id);
}
```

and `engine.rs:280-288` decides that disposition purely by whether the peer already existed:

```rust
let disposition = if previous_endpoint.is_some() {
    ConfigurePeerDisposition::Replaced
} else {
    ConfigurePeerDisposition::Added
};
```

`Replaced` therefore means "this peer was already configured", NOT "its key changed". Note the clear
itself is locally CORRECT: `configure_peer` builds a fresh `Tunn::new(...)` on every call
(`engine.rs:~266`), so the crypto session really is torn down and rebuilt and any earlier handshake
timestamp really is stale.

**So the defect is upstream of the clear:** the reconcile path calls `configure_peer` for a peer
whose configuration has not changed, which rebuilds the WireGuard session and discards the handshake
record every cycle. That accounts for every observation at once — `path_live_peer_count=0`
permanently, no readable handshake age at baseline, and traffic nevertheless flowing (each rebuild
re-handshakes, so the data path recovers while the record never survives long enough to be read).

**The fix is a session-lifecycle change, and it must not be rushed.** The correct shape is for
`configure_peer` to be a no-op when the peer's material has not changed (same public key, same
allowed IPs, same endpoint), so an unchanged reconcile neither rebuilds `Tunn` nor clears telemetry —
NOT to weaken the clear, which would leave a stale timestamp attached to a genuinely new session and
make `handshake_fresh` lie. Verify with the module's own unit tests: configure the same peer twice
and assert the disposition and that a recorded handshake survives the second call, then assert it is
still cleared when the public key or allowed IPs actually change. This sits in the crypto/dataplane
path, so it needs its own implementation pass with those tests written first.

**Superseded framing:** why does `HandshakeTelemetry` hold nothing for the
client's peer on a run where `live_two_hop_validation` passes and therefore proves encrypted traffic
is flowing through that client. Either the engine returns `None` for the handshake shapes this peer
actually performs, or the telemetry is cleared (`clear_peer`, `:564`/`:616`) by something in the
reconcile path. Both are testable against the existing unit tests in that module without a lab run.

**Deliberately NOT attempted here.** This is the crypto/dataplane path, and a speculative change to
handshake accounting is exactly the shape of edit this project treats as release-blocking when it
goes wrong. It needs its own implementation pass with the module's own tests, not a tail-end patch.

**What the repaired instrument reveals — the real, remaining defect.** The client reports
`path_live_peer_count=0` and NO readable handshake timestamp, at baseline, on a run where
`live_two_hop_validation` passes and therefore proves traffic is flowing. So the daemon never records
a probe handshake for this peer even while the tunnel demonstrably works. The next step is to
establish why `traversal_probe_statuses` carries no timestamp for the client's peer — whether the
probe never runs for a bundle-programmed peer, or runs and records nothing — and NOT to touch the
stage again. Note also that `traversal_probe_latest_handshake_unix` renders as the literal
`multiple` on a node with more than one peer, so any per-node aggregate is the wrong source for a
per-peer age; a per-peer field is needed.

**Superseded note, kept for the record.** The stage is STRUCTURALLY UNPASSABLE as written, independently
of daemon behaviour. Do not attempt another daemon-side fix until the measurement is repaired.**

Run `qh51-keepalive-20260814d` reports:

```
timings.baseline_handshake_age_s = 18446744073709551615   <-- u64::MAX at BASELINE
checks.wg_disruption_confirmed   = pass
checks.wg_handshake_recovered    = fail
```

`u64::MAX` **before any block is applied**. The age is unreadable at every point in the stage, not
just after the flap, so `disruption_confirmed` passes trivially (`u64::MAX >= 30`) while
`wg_handshake_recovered` can never pass (`u64::MAX < 30` is never true). The stage cannot report
success no matter what the daemon does.

**Mechanism.** The daemon renders the field as the literal string `"none"` when there is no live
handshake (`daemon.rs:6092`, netcheck; the same shape at `:8092` for status):

```rust
path_state.latest_live_handshake_unix
    .map_or_else(|| "none".to_owned(), |value| value.to_string());
```

`parse_handshake_age_s_from_netcheck` (`live_linux_network_flap_test.rs:350`) parses with
`.parse::<u64>().ok()`, so `"none"` fails to parse, the `if let Some(ts)` arm never matches, and
control falls through to the function's trailing `u64::MAX`. That value is therefore returned for
THREE different states — token absent, token present as `"none"`, and clock skew (`now < ts`) — which
the stage then treats as a single enormous age.

**Consequences, in the order they should be fixed:**

1. **The measurement must distinguish "unreadable" from "old".** A metric that cannot be read is not
   evidence of disruption, and mapping it to a maximal age manufactures a passing check out of
   missing data. Until this is fixed, `wg_disruption_confirmed = pass` on this stage means nothing.
2. **Then establish why the client reports no live handshake at BASELINE**, when
   `live_two_hop_validation` passes on the same run and therefore proves traffic is flowing through
   it. Either `latest_live_handshake_unix` is only populated for peers that completed a traversal
   probe (so a bundle-programmed peer legitimately reports `none`), or the client genuinely has no
   live-proven handshake while forwarding. Those are different defects and the fix differs.

**Already landed and NOT the cause:** managed peers now carry a 25s persistent keepalive
(`MANAGED_PEER_PERSISTENT_KEEPALIVE_SECS`). That was a real dormant-feature defect — the privileged
helper had validated and emitted the argument since FIS-0015 while the only `Some(..)` in the
repository was a helper unit test — and it is correct on its own merits. It did not change this
stage's verdict, and given the measurement defect above it COULD not have. Newly surfaced on run `qh46-firewalld-20260814c`
(35 passed / 1 failed / 23 skipped) — this stage had been cascade-blocked behind
`live_two_hop_validation` and had never run to its own verdict before [[QH-46]] was fixed.

The stage blocks WireGuard's UDP output on the client, waits for the keepalive to lapse, confirms the
disruption, removes the block, then polls for handshake recovery:

```
[network-flap] blocking WG UDP output port 51820 on client
[network-flap] block rule added=true
[network-flap] waiting 35s for keepalive to expire
[network-flap] mid_handshake_age_s=18446744073709551615 disruption_confirmed=true
[network-flap] removing block rule
[network-flap] polling for WG handshake recovery
[network-flap] recovery_arrived=false recovery_time_s=0
[network-flap] tunnel_active=true membership_intact=true
```

So the tunnel is up and membership is intact, but no fresh handshake is observed after the block is
lifted.

**Two separate things to run down, and they must not be conflated:**

1. **`mid_handshake_age_s = 18446744073709551615` is `u64::MAX`**, not an age. That is a sentinel or
   an unsigned underflow (`now - last_handshake` with `last_handshake` in the future or zero) leaking
   into a field the stage then reasons about. It happens to produce the right verdict here —
   "extremely old" reads as disrupted — which is exactly what makes it dangerous: a value that is
   wrong for the right reason will keep passing until it silently isn't. Fix the arithmetic
   regardless of whether it is this stage's cause.
2. **Why no handshake returns.** WireGuard re-handshakes when it has traffic to send, and the stage
   explicitly waits for the keepalive to lapse first. Worth establishing, in this order: whether a
   persistent keepalive is actually configured on the client peer after the flap; whether the peer's
   endpoint survived the block or was demoted; and whether anything generates traffic during the
   recovery poll at all. A poll that observes a silent tunnel proves nothing about recovery.

**One contributing factor already ruled OUT as the cause.** The journal shows
`flap breaker for peer fedora-utm-1-bootstrap half_open -> open (intensity 0.97)`, and an open
breaker is real: `daemon.rs:6885` skips the re-race while it is not closed. But it gates only the
QUALITY-TRIGGERED re-race, not WireGuard's own handshake, so it cannot by itself explain a missing
handshake. It may still matter if recovery depends on re-selecting an endpoint — do not dismiss it,
but do not treat it as the answer either.

### QH-46 — two-hop proof: the client reaches the entry but never the final exit

**Status: FIXED and LIVE-PROVEN 2026-08-14. `live_two_hop_validation` PASSED for the first time in
the recorded history of the `--node` engine**, on run `qh46-firewalld-20260814c`, with a
firewalld-family (Fedora) entry node — the only topology in which the test is meaningful.

From the stage's own report artifact, not a ledger column:

```
end_to_end_reachable       = True     (was False)
baseline_reply_ttl         = 64
two_hop_reply_ttl          = 63       (was -1)
per_hop_ttl_decrement      = 1        (was none)
per_hop_ttl_decrement_ok   = True
path_readiness_attempts    = 1        (was 11 attempts over 96s, never reachable)
path_readiness_waited_secs = 2        (was 96)
entry_host                 = fedora@192.168.64.103
```

TTL 63 is exactly one forwarding hop, and it is the SAME value the historical Debian-entry runs of
2026-06-27 produced. That is what closes the diagnosis: firewalld was the entire difference, and a
firewalld-family node now forwards identically to one that never ran firewalld. Run result overall:
35 passed / 1 failed / 23 skipped, the remaining failure being `live_network_flap_validation`, a
stage that had been cascade-blocked behind this one and reached its own verdict for the first time.

The root cause, the fix, and the refuted hypotheses are kept below so the reasoning stays auditable.**

Rustynet installs its forward chain at `type filter hook forward priority 0` and appends the relay
hairpin allow `iifname rustynet0 oifname rustynet0 counter accept` (`phase10.rs:2265-2294`). In
netfilter a base chain's `accept` is `NF_ACCEPT` — "continue to the next base chain at this hook" —
not a final verdict. A chain at the same hook with a higher priority number still runs on the same
packet and can drop it.

Measured directly on the entry (`fedora-utm-1`, 192.168.64.103):

```
systemctl is-active firewalld  ->  active

table inet firewalld {
  chain filter_FORWARD {
    type filter hook forward priority filter + 10; policy accept;
    ct state { established, related } accept
    ct status dnat accept
    iifname "lo" accept
    ct state invalid drop
    ip6 daddr { ... } reject with icmpv6 addr-unreachable
    jump filter_FORWARD_POLICIES
    reject with icmpx admin-prohibited          <-- the hairpin dies here
  }
}

firewall-cmd --get-active-zones                 ->  FedoraServer (default), interfaces: enp0s1
firewall-cmd --get-zone-of-interface=rustynet0  ->  no zone
```

`rustynet0` is created at runtime by the daemon, not by NetworkManager, so firewalld binds it to no
zone; `filter_FORWARD_POLICIES` does not accept it and the chain falls through to its final `reject`.
The packet is destroyed BETWEEN the FORWARD and POSTROUTING hooks. That is exactly why the hairpin
forward counter advances while the hairpin masquerade counter stays at zero — the masquerade sits on
a later hook the packet never reaches. No rule Rustynet installs is wrong; the one it needs to
survive belongs to another firewall.

**This accounts for the whole history of the stage.** Across every dataplane-bearing two-hop report
on disk, the only runs that recorded a genuinely forwarded reply (TTL 63, exactly one hop) had a
**Debian** entry, on 2026-06-27. Every run whose entry was a firewalld-family guest (Rocky, later
Fedora) produced either a decrement-0 reply that bypassed the entry via the since-removed direct
client-to-exit peer, or no reply at all. Debian does not run firewalld by default; Fedora, RHEL,
Rocky, Alma and CentOS do. The `--node` engine elects Fedora or Rocky as entry, which is why this
stage has never passed on it while the frozen bash archive shows passes.

**Scope — release-blocking, not lab hygiene.** Any RHEL-family host running the distribution default
cannot serve as a Rustynet relay or exit forwarder. The product has no awareness of firewalld
anywhere: the only references are the lab bootstrap
(`scripts/bootstrap/linux/rn_bootstrap.sh:404-421`), which opens `51820/udp` for INPUT and does
nothing about the forward path, and a test asserting the bootstrap does not stop firewalld. This
contradicts the parity mandate that no OS may be a capability limiter.

**Fix direction — NOT implemented; it changes host firewall state and needs plan-then-adversarial
review.** Industry precedent is to place the tunnel interface in a firewalld zone that permits it
(Tailscale does this for `tailscale0`). Note precisely what that does and does not concede:
Rustynet's own priority-0 chain keeps `policy drop` and continues to enforce default-deny and its
ACLs, so the change stops firewalld rejecting traffic Rustynet has ALREADY authorised rather than
authorising anything new. It still mutates host firewall configuration, so it must go through the
privileged helper as an argv-only, strictly validated operation with its own narrow allowlist entry
(§4), must fail closed when firewalld is present but the operation fails, and must be a no-op where
firewalld is absent. Do NOT fix this in the lab bootstrap alone — that converts a real product gap
into a lab-only workaround and hides it from every user on a RHEL-family host.

`live_two_hop_validation` reached its own verdict for the first time in
`qh45-final-20260813u`, after three blockers were cleared in sequence: the vmnet split
(topology), the missing `entry` role, and the nft allowlist refusals (QH-45). It fails:

```
end_to_end_reachable=false  per_hop_ttl_decrement=none  per_hop_ttl_decrement_ok=false
```

**The structured report isolates it precisely** (`live_two_hop_report.json`):

```
baseline_entry_mesh_ipv4:     100.123.159.114   baseline_reply_ttl: 64    <- entry REACHABLE
two_hop_final_exit_mesh_ipv4: 100.80.169.183    two_hop_reply_ttl: -1     <- exit NOT reachable
end_to_end_probe_target: 1.1.1.1                end_to_end_reachable: false
path_readiness: 11 attempts over 96s, never became reachable
```

So the shape is **client → entry works; entry → final exit does not**. The stage waited 96
seconds across 11 attempts, so this is durable, not a startup race.

### Two hypotheses this entry previously carried, both refuted by measurement

1. **"Packets are not being forwarded by the entry."** False. Sampled live on the entry during
   the stage, the hairpin rule shows real traffic:
   `iifname "rustynet0" oifname "rustynet0" counter packets 27 bytes 2052 accept`, with
   `ip_forward=1`. Traffic transits the entry; it just never reaches the final exit. (That
   counter is readable only because QH-45 allowlisted the `counter` token — the fix that made
   the stage runnable also made it diagnosable.)
2. **"`ip_forward=0` at stage start is a race."** False. The stage enables forwarding itself via
   its `advertising default route on final exit and entry relay` step; samples that straddle
   that step see the transition, which is normal sequencing.

`per_hop_ttl_decrement=-1` is likewise not "no forwarding observed" — it is arithmetic on a probe
that received no reply at all.

**ROOT CAUSE (confirmed live):** the final exit has **no return route to the client's mesh
address**, so replies leak out the physical LAN interface and die.

Captured on the exit during the stage:

```
node_role=admin  serving_exit_node=true  path_programmed_peer_count=2
managed_peer_endpoints=fedora-utm-1-bootstrap/192.168.64.103:51820+rocky-utm-1-bootstrap/192.168.64.105:51820

ip route get 100.124.191.164        # the client's mesh address
  → via 192.168.64.1 dev enp0s1     # the LAN gateway, NOT rustynet0
```

Nothing in the exit's peer set claims `100.124.191.164`. Its peers are the entry
(`fedora-utm-1`) and the second client (`rocky-utm-1`); the two-hop client
(`debian-headless-4`) appears nowhere, so no `AllowedIPs` entry installs a tunnel route for it.
Return traffic therefore matches the default route and egresses `enp0s1` toward the LAN gateway,
where `100.64.0.0/10` is unroutable and is dropped.

That accounts for every observation without contradiction: the client's route to both mesh
addresses is identical (`dev rustynet0 table 51820`), the entry genuinely forwards
(27 packets / 2052 bytes on the hairpin rule), the entry's own mesh address answers with TTL 64,
and only the exit's address never replies. The request path works; the reply path does not exist.

**Note on instrumentation:** `wg show` cannot inspect this — the lab runs the userspace backend
(`transport_socket_identity_label=wireguard-linux-userspace-shared-authoritative-transport`), so
the kernel tool reports `Unable to access interface: Operation not supported`. Use
`rustynet status` (`managed_peer_endpoints`) and `ip route get`, which is what produced the
capture above.

**ROOT CAUSE (confirmed, same-sample): the hairpin SNAT the design depends on can never match
under the userspace WireGuard backend.**

The exit's missing client peer is BY DESIGN. The two-hop test states the intended mechanism above
its own ALLOW_SPEC:

> entry masquerades the hairpin (`phase10.rs:2285-2299`) — that SNAT is what gives the final exit
> a route to the requester, since after this strip its peers carry only `entry/32` and
> `second_client/32`.

So the return path is supposed to come from the entry's SNAT. Captured on the entry, mid-stage,
in a SINGLE sample (counters from different runs are not comparable):

```
serving_exit_node=true      exit_node=debian-headless-2-bootstrap

FILTER  inet rustynet_g2 / forward:
  iifname "rustynet0" oifname "rustynet0" counter packets 36 bytes 2808 accept
NAT     ip rustynet_nat_g2 / postrouting:
  iifname "rustynet0" oifname "rustynet0" counter packets 0 bytes 0 masquerade
```

Traffic forwards (36 packets) and is never SNATed (0 packets), so the exit keeps seeing the
client's mesh source address, has no peer claiming it, and its replies leave via the LAN default
route — which is what `two_hop_reply_ttl: -1` records.

**CORRECTION — the mechanism I first recorded here was wrong.** I wrote that the rule cannot match
because the userspace backend re-encrypts the packet and emits it on the physical interface. That
conflates two different packets. `rustynet0` is a real TUN device under the userspace backend too,
and a kernel forward *out* a TUN device does traverse the nat postrouting hook with
`oifname "rustynet0"`. The re-encrypted UDP datagram is a separate, locally generated packet. The
observation below stands; the explanation I attached to it does not, and no fix should be built on
it.

**What is actually established:** the rule is installed, `serving_exit_node=true`, and the rule's
counter is zero. That is all.

**SAMPLING FLAW — the 78-byte inference is void.** The capture fired 60s after the stage started,
but `path_readiness` alone runs ~96s before the probe sends its first ping. The sample therefore
almost certainly predates any probe traffic, and the 36 packets at 78 bytes each are whatever was
flowing at that moment (gossip). "No 84-byte packets in the counter" says nothing about whether
pings were forwarded later. A single mid-stage sample cannot answer this question; only a
time series across the probe window can.

**Topology is confirmed correct, from the node status lines of run `qh46-snat-20260813x`:**

| node | role | peers |
| --- | --- | --- |
| debian-headless-4 | client | entry only (fedora) |
| fedora-utm-1 | entry, `serving_exit_node=true` | exit + client |
| debian-headless-2 | final exit | entry + second client, no client peer (per ALLOW_SPEC) |

So the failure mode the SNAT exists to prevent is real and correctly identified: the client pings the
exit's mesh IP, the exit receives it carrying the client's source address, no peer claims that
address, and the reply leaves by the LAN default route. The design is coherent and the masquerade is
load-bearing. What remains unexplained is only why its counter is zero.

**THE TWO COUNTERS ARE NOT COMPARABLE — this probably dissolves the anomaly.** The forward rule is in
table `inet rustynet_g2`. The `inet` family matches IPv4 *and* IPv6, and that rule carries no
address-family qualifier, so it counts both. The masquerade is in `ip rustynet_nat_g2`, which is
IPv4-only. IPv6 traffic therefore increments the forward counter and can never reach the nat table,
by design and with nothing wrong.

The measured size fits that reading: 40 bytes of IPv6 header + 8 of UDP + 30 of payload = 78, which
is exactly the per-packet figure. So the 36 packets are plausibly IPv6 gossip transiting the entry,
and `forward 36 / nat 0` is not evidence of a defect at all. Any future comparison of these two
counters must first establish that both are observing the same address family; otherwise it compares
a v4+v6 counter against a v4-only one and manufactures a contradiction.

**The decisive test** is a TIME SERIES, not a single sample: poll the entry's filter and nat hairpin
counters together every 10s for the whole stage, so the probe window is captured wherever it falls.
A filter delta with no matching nat delta means the SNAT chain is not being traversed (candidate 1,
conntrack state). No delta in either across the entire stage means the probe never reaches the
entry (candidate 2). It must run mid-stage because `final_cleanup` is `always_run` and removes these
tables, and both counters must come from one sample because counters from different runs are not
comparable.

**Not yet established, and it decides the fix:** whether this is (a) a genuine backend gap — the
SNAT needs a different expression under userspace WG, or the return route must be supplied some
other way — or (b) a lab configuration issue, i.e. two-hop is only expected to pass on the kernel
backend and the lab should elect that backend for this stage. Settle it before writing code; both
`allow_tunnel_relay_forward` gating and the ALLOW_SPEC strip are correct as written under (a),
and untouched under (b).

**Instrumentation notes for whoever continues:** `wg show` cannot inspect a userspace interface
(`Operation not supported`) — use `rustynet status`. `final_cleanup` is `always_run`, so all of
the above must be captured mid-stage. Counters must be read in one sample; comparing a filter
counter from one run against a nat counter from another proves nothing.

**QH-51 CONFIGURE_PEER NO-OP: runtime contract pinned (2026-08-21) — unit- and mutation-proven;
not yet live-proven.** The prescribed session-lifecycle fix itself was already on the engine of
record at `4148cdae`: `configure_peer` returns `Unchanged` for identical material and
`EndpointMoved` for an endpoint-only change without rebuilding the `Tunn`, and both runtimes
(linux + macOS userspace-shared) clear handshake telemetry ONLY on `Replaced` — exactly the shape
above, including the deliberate refusal to weaken the clear. What was MISSING was this ledger's
prescribed verification at the RUNTIME level ("a recorded handshake survives the second call ...
still cleared when the public key or allowed IPs actually change"): the engine tests pinned only
disposition + session identity (`tunnel_index`), and nothing asserted what happens to the
telemetry record. Added six runtime-level tests, linux and macOS mirrors of each half:
`{linux,macos}_runtime_identical_reconfigure_keeps_recorded_handshake`,
`{linux,macos}_runtime_endpoint_only_reconfigure_keeps_recorded_handshake_and_moves_the_peer`
(also asserts the peer actually moved), and
`{linux,macos}_runtime_replaced_peer_material_clears_recorded_handshake` (public-key and
allowed-IP variants — the stale-timestamp-must-not-survive half). Mutation-proven in the worktree
at base `4148cdae`: (M1) making BOTH runtimes clear on any disposition → the 4 survival tests fail
(rc 101); (M2) removing the clear entirely → the 2 clears tests fail (rc 101); (M3) disabling the
engine's unchanged/roam guard so every re-apply rebuilds → all 8 fail (the 6 new plus the two
pre-existing engine QH-51 pins) (rc 101); restored between mutations from backup, final state
green (rc 0). Gates at the same tree: fmt rc 0; clippy `-p rustynetd` and
`-p rustynet-backend-wireguard` (`--all-targets --all-features --locked -D warnings`) rc 0;
`cargo test -p rustynetd --all-targets --all-features --locked` rc 0 (2265 passed);
`cargo test -p rustynet-backend-wireguard --all-targets --all-features --locked` rc 0.
Caveat: these pins prove the reconcile no longer destroys the RECORD; whether a post-flap
reconcile actually restores handshakes within the stage's recovery window is still governed by
the open probe-pacing question above and remains unproven until a live run samples
`traversal_probe_next_reprobe_unix` / `traversal_probe_attempts` per the capture protocol.


### QH-52 — the firewalld zone bind is never undone: role demotion leaves the binding behind

Found by adversarial review of the [[QH-46]] enforcement tests, not by a failure. `FirewalldZoneOp`
has `Bind`, `Unbind` and `Query`, but the daemon's ONLY constructor call site is the `Bind` in
`ensure_host_firewall_admits_forwarding` (phase10.rs:893) — `Unbind` and `Query` have zero callers.
A node that stops forwarding (relay/exit demotion, `rollback_firewall` phase10.rs:2357) never
removes the interface-to-zone binding. The residue is bounded — the binding is runtime-only
(the D-Bus method deliberately avoids the persistent NetworkManager write) and dies with
firewalld or the interface — but the asymmetry violates the §10.7 shape ("undeploy before
revocation") and should either gain an `Unbind` call on the demotion path or a documented
decision that the bounded residue is acceptable.

### QH-53 — REGRESSION from the QH-46 fix: firewalld bind races interface creation on daemon
restart, and a failed bootstrap apply is never retried

**Two defects compounding, live-proven on run `qh51-peerprobe2-20260814q` (fedora, 11:36:02Z):**

1. `ensure_host_firewall_admits_forwarding` runs at the tail of `apply_firewall_killswitch`
   (phase10.rs:2351), which runs BEFORE tunnel interface creation (fail-closed-first ordering).
   On a firewalld host the builtin's virtual-device guard
   (`require_virtual_network_device`, privileged_helper.rs:1264) then refuses the bind if
   `rustynet0` does not exist yet, failing the WHOLE dataplane apply. The same fedora daemon
   restarted cleanly at 11:32:04 (21s stop→start gap) and fatally at 11:36:02 (2s gap) with the
   same role state — a race against interface teardown/creation timing, not deterministic
   ordering. Debian-family hosts escape only because `presence=Absent` short-circuits before the
   device check (privileged_helper.rs:1103).
2. When the bootstrap apply fails, the daemon logs `restrict_recoverable: dataplane bootstrap
   apply failed`, then reports `runtime bootstrap complete` and sits with NO tunnel interface
   indefinitely (observed 5+ minutes until the run's cleanup) — `restrict_recoverable` has no
   retry loop for the dataplane apply. A forwarding node on a firewalld distribution can
   therefore drop out of the mesh on any fast daemon restart and stay out silently.

Consequence for [[QH-51]]: run 40's `recovery_arrived=false` is contaminated (the client's peer
was tunnel-less), so flap hypothesis 8 remains open. The trigger in the lab is `managed_dns`
bundle propagation, which restarts each node's daemon with a ~2s gap.

~~Fix is NOT designed yet~~ — superseded: the fix went through the full PLAN → ADVERSARIAL REVIEW
→ IMPLEMENT → REVIEW cycle and landed 2026-08-15 (see the FIX LANDED section below). The
investigation additionally established this was never a race within one apply: the ordering was
deterministic (bind strictly before `backend.start`, the only interface creator), and every
historical success was a warm re-apply against an already-live interface. The virtual-device
guard and the fail-closed verdict were NOT weakened.

**QH-53 FIX LANDED (2026-08-15) — unit- and mutation-proven; live proof pending the next lab run.**
The zone bind is now its own `DataplaneSystem` stage, `admit_host_firewall_forwarding`, called by
the controller AFTER `backend.start` (which creates the interface) and before the serving stages,
still ahead of generation commit — so an obstructing host firewall fails the apply before the
role is advertised, and the 1s reconcile retry can now converge instead of re-entering a
deterministically broken ordering. Scoping note: "advertised" here means the generation commit +
on-Ok daemon sync (gossip data-plane sync also runs at the membership-apply and refresh seams
regardless of dataplane state, but that is mesh participation, not forwarding-role advertisement —
peers route to an exit from their own signed bundles).

Review-driven hardenings beyond the ordering move:

* **The gate is `serve_exit_node`, not `relay_with_upstream`.** A terminal exit and `blind_exit`
  (both `exit_mode Off`) forward through the same FORWARD hook firewalld rejects; the original
  QH-46 gate left them unbound — never observed live only because the lab's exits are
  Debian-family. Until a firewalld-family (Fedora/Rocky) exit topology runs live, the exit-shaped
  cell is unit-proven only.
* **Single controller gate, deliberate.** The Linux impl verifies unconditionally when called;
  a kept impl-level `allow_tunnel_relay_forward` gate would silently no-op the stage for exactly
  the terminal-exit/blind_exit cases the widening covers (their flag is false). Failure direction
  of the unconditional check is strictly more fail-closed.
* **The trait method is deliberately NOT defaulted.** The production `RuntimeSystem` dispatches
  trait methods arm-by-arm; with a defaulted method, an omitted dispatch arm would silently
  no-op the enforcement on the real daemon while every DryRun-driven test stayed green. The
  source pin additionally pins the Linux dispatch arm text.

Verification: 12 mutations, all caught — macOS (delete call site, remove controller gate,
relocate the call above backend.start, swallow the controller error, stub the RuntimeSystem arm,
reintroduce the killswitch tail call, gut the check) and the Debian guest (swallow the
run_capture error, missing-bound-as-clear, hardcoded interface, Bind→Query swap, reintroduce the
tail call at the behavioural layer). Full rustynetd suite 2055 passed on macOS; the 10
admit-stage tests pass on the Debian guest; full Linux workspace suite on ubuntu-kvm-1 shows
only 5 pre-existing environment/concurrency failures in rustynet-cli vm_lab tests, unrelated
(they fail or collide identically on clean main; filed separately).

### QH-54 — worker-death recovery recreates the tunnel interface without re-binding firewalld

`recover_runtime_after_worker_exit` (userspace_shared/mod.rs:214-265) does `ip link del` +
recreate with no firewalld re-bind. firewalld's runtime zone binding may not survive the
delete/recreate, so a forwarding node that survives a worker crash can lose its bind until the
next full apply. Pre-existing (the old pre-start bind had the same hole); made explicit by the
[[QH-53]] review. Availability-only, never fail-open: on a firewalld host a lost bind surfaces
as the next apply failing closed. Needs either a re-bind hook in the recovery path or a periodic
posture assert.

**`--node` test-surface clarification (2026-08-17).** Do not count
`chaos_daemon_fault` as QH-54 proof. Its Rust `--node` stage invokes
`live_chaos_daemon_fault_test`, which kills or SIGSTOP/SIGCONTs the *whole* systemd daemon, then
observes service/socket recovery plus client-side no-plaintext-egress. That starts a new daemon;
it cannot exercise `recover_runtime_after_worker_exit`, which is reached only when a still-running
backend receives the worker-unavailable control error. The existing test-only seam is correctly
kept out of the shipping daemon: a next-TUN-receive error causes the worker to exit, then the
daemon tests prove authoritative transport becomes unavailable and a bounded authoritative
round-trip recovers it. Re-checked at `dea73a75`: both
`daemon_runtime_linux_userspace_shared_backend_recovers_authoritative_transport_after_worker_exit`
and its macOS counterpart pass under `cargo test -p rustynetd --lib --all-features --locked`.

The current production call graph serializes backend operations through `&mut self`; a repository
search found `RuntimeControl::clone()` only in backend tests. Those tests already reject a second
concurrent round-trip and prove shutdown cancels an in-flight round-trip. Therefore no general
shutdown race is claimed here. Keep any future configure/stats/send-versus-shutdown stress test as
a regression guard for this cloneable internal control, not as a confirmed production defect. The
actual open coverage is the post-recovery firewalld binding. Do not add a production IPC/SSH
"crash worker" control merely to make it live-lab-testable. A future `--node` stage may consume a
read-only recovery-status artifact only after the backend contract and a safe fault mechanism
exist; until then it must not claim QH-54 live proof.

**`--node` placement constraint (2026-08-17).** Even once QH-54 has a safe test surface, it must
not be added to the current chaos macro merely because it is a fault test. All nine chaos stages
and every cross-network stage declare `live_mixed_topology_validation` as their sole prerequisite.
That stage intentionally returns `Skipped` unless Linux, macOS, and Windows are all assigned, and
the runner then recursively skip-cascades its descendants. A worker-recovery/firewalld check would
therefore be silently unavailable on the Linux-only firewalld lab where this defect is most
actionable. Focused runner, plan, and chaos metadata tests pass at `dea73a75` and confirm both
the cascade and the nine-stage macro shape.

The future item should be a dedicated, capability-gated validation with its own evidence artifact:
baseline runtime healthy; recovery event observed through a read-only contract; firewalld binding
queried after recreation; then the authoritative transport and dataplane verdict rechecked. Its
true prerequisites and any destructive ordering belong in the QH-48 design which separates
"runs after" from "must have passed". Do not borrow `live_mixed_topology_validation` as a generic
ordering anchor, and do not claim this as live proof until the fault mechanism, rebind fix, and
stage artifact all exist.

**Shared UDP transport lifecycle deep dive (2026-08-17; source + focused-test grounded).** The
Standalone consolidation: [Shared UDP / Relay Transport Deep Dive — 2026-08-17](SharedUdpRelayTransportDeepDive_2026-08-17.md).

core D3 ownership model is sound. The userspace runtime owns one `AuthoritativeSocket`; peer
ciphertext, STUN request/response, relay hello, and relay keepalive all use that socket. The
backend rejects an authoritative round trip aimed at a configured peer endpoint, so a control
reply cannot consume peer ciphertext. `RelayClient` has no production socket fallback: its
convenience establish/keepalive methods fail and the daemon supplies backend round-trip/send
closures. Command-only backends remain explicitly blocked rather than pretending that a second
same-port UDP socket is authority.

The subtler lifecycle boundary is **socket incarnation**, not local address. Each userspace socket
receives a process-local monotonic `transport_generation`; a restart/recovery can bind the same
address and port while receiving a new generation. The Linux test deliberately proves exactly
that shape, and both Linux/macOS tests prove generation replacement. Internally, an outstanding
round trip carries the generation and a late packet cannot satisfy the new waiter; that is good.
But `AuthoritativeTransportIdentity`, `AuthoritativeTransportResponse`, daemon `status`, and
`netcheck` expose only label + local address. A live observer therefore cannot distinguish the
old socket from a recovered socket that reused the port. The existing daemon recovery tests prove
only unavailable -> available plus a successful round trip, not that the reported socket
incarnation changed.

This matters operationally after an in-process recovery. `with_runtime_recovery` recreates the
socket and returns the retried operation normally, but provides no recovery/lifecycle event to
`DaemonRuntime`. Cached STUN observations and candidates refresh on their normal 60-second
schedule; daemon endpoint-change detection observes traversal hints and gateway state, not the
authoritative socket incarnation. Existing relay-session objects are likewise retained. A NAT may
preserve the mapping for the same local tuple, so stale state is **not claimed as a proven live
failure**; it is simply no longer proven valid after a new socket and may delay recovery or
advertise a stale srflx candidate. Ciphertext-only/fail-closed behavior is unchanged.
The relay validates hello, data, and keepalive traffic against its recorded source tuple, so a
reused local port alone cannot establish post-rollover relay-session continuity.

**Recommended lifecycle contract — design before implementation.** Add an opaque, process-local
transport-incarnation value to the authoritative identity/response contract (not a security
credential and not cross-daemon persistent state). When the explicit daemon recovery coordinator
observes unavailable -> available with a new incarnation, it should: clear cached STUN observations and
srflx candidates; schedule STUN immediately; discard relay-session/pending-keepalive state whose
continuity is no longer evidenced; and force the normal signed traversal re-probe/re-establishment
path. Emit the incarnation in the read-only status/netcheck output so the future `--node` stage
can record before/unavailable/after evidence without a diagnostic fault-control surface. Add Linux
and macOS tests for same-port recovery, immediate invalidation, fresh STUN observation, and relay
session re-establishment. Do not equate a reused local port with continuity.

**Worker-control hardening (separate follow-up, not a confirmed production defect).** Recovery
currently recognizes a dead worker by two exact `BackendErrorKind::Internal` message strings; the
backend error taxonomy has no worker-unavailable variant. Editing either string can silently turn
a detectable worker exit into an opaque availability failure. Add a typed
worker-unavailable/indeterminate classification before any recovery behavior, preserving all other
`Internal` errors as non-retryable. Only the daemon-owned coordinator may recover; no caller gets
permission to retry its original operation. The Linux/macOS runtime worker also uses an unbounded command
channel and drains commands until empty before timers/UDP/TUN polling. Production backend calls
currently serialize through `&mut self`, and repository search found `RuntimeControl::clone()` only
in tests, so command-flood starvation is not claimed as a present production incident. Still,
before this internal control is ever shared, retain commands-first ordering but bound both command
admission and commands drained per tick, with explicit overload/closing semantics and parity tests.
Do not add caller timeouts alone: an ambiguous timeout after a queued mutation would require an
epoch/acknowledgement contract first.

**External-practice check and implementation shape (2026-08-17; online research, not live-lab
proof).** This direction matches published practice from large secure-network operators. Tailscale
states that STUN and tunnel traffic must use the *same* socket because each socket can receive a
different NAT mapping, and it treats relay as required fallback for hard or hostile networks
([NAT traversal guide](https://tailscale.com/blog/how-nat-traversal-works)). Cloudflare describes
UDP tuple changes caused by NAT rebinding as breaking tuple-only connection tracking; QUIC avoids
that only because its authenticated protocol owns a separate connection identifier
([Cloudflare QUIC analysis](https://blog.cloudflare.com/the-road-to-quic/)). Rustynet's relay is
tuple-bound and its existing protocol has no equivalent migration identifier, therefore it should
reset/re-register rather than invent continuity from an unchanged port. This is a correctness and
availability decision, not a claim that the reused-port case is an attack or proven outage.

The standards and operators also reject a universal timer assumption. RFC 4787 defines UDP mapping
as a session/tuple property, allows endpoint-dependent mappings, and requires clients to tolerate
port preservation *and* non-preservation
([RFC 4787](https://datatracker.ietf.org/doc/html/rfc4787.html)). Cloudflare notes real UDP NAT
timeouts can be arbitrary and short
([stateful UDP operations](https://blog.cloudflare.com/the-road-to-quic/)); Tailscale's active
periodic re-STUN interval is roughly 20--26 seconds in its
[current open-source client](https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/magicsock.go#L3688-L3717), whereas
Rustynet's normal interval is 60 seconds. Do **not** globally copy either value: recovery must
schedule an immediate, rate-limited re-probe; a future normal keepalive interval requires measured
live-lab NAT coverage, battery/packet-budget analysis, and a separately approved policy. Fortinet
exposes both per-service UDP idle timers and concurrent UDP-session limits in its CGNAT/firewall
products ([session-timer guide](https://docs.fortinet.com/document/fortigate/7.4.6/fortinet-carrier-grade-nat-field-reference-architecture-guide/863546/session-timers)). That reinforces that an
application cannot infer NAT state from its own bound port.

**P1 implementation: one authoritative transport transition.** First add an opaque
`TransportIncarnation(u64)` to `AuthoritativeTransportIdentity`; it is process-local, monotonically
changes whenever the backend creates a new authoritative socket, and is neither persistent identity
nor a security token. Every authoritative operation must report the captured incarnation: extend
round-trip receipts/responses, and make send return a small receipt or a fresh identity. This is
diagnostic evidence for the later explicit coordinator; it does **not** make a hidden
`with_runtime_recovery` safe. That helper must be removed/replaced so no recovery occurs in an
authoritative operation, non-authoritative query, or desired-state operation without daemon
quarantine first. Backend adapters unable to prove a stable incarnation expose an `Unobservable`
capability plus an explicit recovery event; a repeated unobservable identity read is not itself a
rollover event.

Add one daemon-owned `observe_authoritative_transport(identity)` transition function. It persists
the last `{backend label, local address, incarnation}` only in runtime memory. First observation is
baseline. `available -> unavailable`, `unavailable -> available`, or a changed known incarnation
creates exactly one `TransportRolledOver` event per observed identity. An unobservable backend
emits the same event only when its explicit recovery signal occurs. On this event, in order:

1. Stop advertising old server-reflexive candidates; clear cached STUN observations/candidates.
2. Invalidate relay registration/session and pending keepalive state; retain encrypted tunnel keys
   and peer configuration.
3. Mark traversal `probing`, enqueue one immediate STUN round (coalesce duplicate transitions),
   then publish signed candidates only from fresh STUN results. Re-register relay independently as
   soon as the new authoritative transport is usable.
4. Emit structured status/netcheck fields: current incarnation, transition reason, count, time,
   STUN freshness, and relay registration state. Do not expose a fault-injection operation.

Run this observer at daemon bootstrap and immediately after the explicit coordinator recovery
call. Every backend operation, including stats/path/handshake reads and desired-state operations,
must instead report its worker fault without healing it. Do not rely on a periodic status read,
because a query can otherwise heal a worker before relay work begins. Debounce recovery storms by
known incarnation: same incarnation is no-op; distinct incarnations each invalidate; exponential
backoff applies to failed STUN/relay work, never to discovering a transition. This is analogous to
Tailscale's practice of publishing endpoints observed from the actual socket and retaining relay
fallback when direct path cannot be proven
([relay/netcheck example](https://tailscale.com/blog/peer-relays-international-networks)).

**P1 proof plan.** Add Linux + macOS deterministic tests which inject one worker failure before
STUN and separately before relay send. Assert: local port may stay equal; incarnation changes;
old candidate immediately disappears from read-only status; exactly one immediate STUN probe is
scheduled; no old relay keepalive is emitted; successful new STUN observation leads to one normal
re-registration. Repeat with worker failure during path-quality and handshake queries: event and
quarantine must complete before the next relay/STUN operation. Race test: delayed old-generation
STUN or relay response cannot repopulate state. Compatibility test: an unobservable backend never
reports false continuity or produces a periodic invalidation storm. Live-lab gate later: record
before/unavailable/after incarnation, candidate age, STUN round count, and relay registration
result under the existing `--node` evidence model.

**P2 implementation: typed worker loss; no string branch.** Add
`BackendErrorKind::WorkerUnavailable`; attach operation class and last known runtime incarnation in
the daemon's separate `TransportFault` record, not an ad-hoc parse of `BackendError.message`.
Worker send failure, dropped reply, and shutdown completion create that kind; retain causal
OS/channel text only for logs. No low-level `with_runtime_recovery` call retries it implicitly:
the daemon recovery coordinator consumes the typed loss, quarantines lifecycle state,
reconstructs once, then runs only a high-level operation explicitly classified as safe. All other
`Internal` errors remain non-retryable. An epoch/operation ID aids diagnosis but cannot prove an
admitted mutation executed before the worker died; return `Indeterminate` unless a desired-state
reconcile proves the outcome. Regression tests must mutate log text while recovery still works,
then verify a generic `Internal` error does **not** recover. This removes a hidden availability
regression class without widening retry scope.

**P3 implementation: bounded control only when concurrency arrives.** Current single mutable
backend owner keeps command pressure low. If a shared controller is introduced, replace unbounded
`mpsc::channel` with bounded admission and a per-tick control budget. `try_send` returning full
must yield a typed `Busy` **before admission**; it is safe to retry with bounded backoff. Once
admitted, mutations receive one epoch/operation acknowledgement and may not be silently dropped.
Worker loop services at most `CONTROL_BUDGET` commands, then timer/UDP/TUN budgets; record queue
depth, admission rejection, longest wait, and per-class service time. Reserve/control-rate-limit
capacity for recovery and shutdown. The exact numbers come from benchmark and soak data, not a
guess. This follows operational pattern used by secure-network providers: Fortinet explicitly
limits concurrent UDP session state, and Tailscale describes fair queueing, overload protection,
and rate limiting for shared relay resources
([FortiProxy session limits](https://docs.fortinet.com/document/fortiproxy/7.2.11/cli-reference/163620/config-firewall-shaper-per-ip-shaper),
[Tailscale relay controls](https://tailscale.com/blog/free-plan)). Add deterministic flood tests
showing UDP/TUN timers still run, queue memory is capped, shutdown wins, and no accepted mutation
is duplicated across recovery. Do not implement this before P2's acknowledgement semantics.

**Adversarial correction — lifecycle implementation gates (2026-08-17; read-only source review).
This supersedes any broader transparent-retry reading above.** The present
`with_runtime_recovery` reruns any closure after replacement, while the worker sends an
authoritative round trip before creating its waiter. That is unsafe for a relay hello: the relay
consumes its nonce before creating a session and rejects replay. If the first hello reaches the
relay but its ACK is lost when the worker dies, retrying the same token is rejected; retrying a new
token consumes another one-use artifact and leaves the client unable to prove which session/ACK won
the race. A fresh accepted hello replaces the prior *same-pair* server session and the relay's
post-commit prune later reclaims its allocation, so this is not claimed as a permanent server leak.
It remains an ambiguous client outcome and consumes recovery inventory. Therefore **no generic
automatic retry** may cover stateful relay hello, registration, allocation, or other externally
visible non-idempotent operation. Return a typed `TransportChanged`/`Indeterminate { operation_id,
old_epoch }` result instead. The daemon then begins explicit recovery with a new,
cryptographically fresh attempt. Protocol-level server deduplication is a separate option, not an
assumption; it needs an attempt key and exact response replay/ack correlation.

An identity/receipt observed only *after* a recovered send is also too late to meet the earlier
"no old keepalive" requirement: a retry could have transmitted that old-session keepalive already.
Backend recovery must instead provide a pre-retry lifecycle outcome, or refuse to retry any
session-bound command. On such an outcome the daemon invalidates relay state first, then sends a
new registration/keepalive only under the new incarnation. `Known(u64)` and `Unobservable` are
separate capabilities: treating every `Unknown` identity read as a changed incarnation would cause
continuous STUN/relay churn, while coalescing it would hide recovery. An unobservable backend needs
an explicit recovery event and conservative invalidation only when that event occurs.

Relay registration must **not** wait for fresh STUN. STUN produces candidate advertisements;
relay registration is independent fallback and must resume once the fresh authoritative socket is
usable, including when STUN is blocked. In parallel, clear old srflx candidates, issue one fresh
STUN transaction with a new transaction/attempt identifier, and publish candidate changes only
from that new result. Current relay ACK processing lacks an attempt/nonce correlation field, so a
delayed parseable old ACK can satisfy a new wait after same-port rebind. Add server-echoed attempt
IDs before claiming delayed ACK resistance. Do not describe this correlation as cryptographic
authentication, and do not add server deduplication merely to obtain it.

Typed `WorkerUnavailable` remains required, but an epoch plus operation ID cannot by itself prove
whether the worker mutated state before dying: current mutators can execute before their in-memory
reply. Automatic replay is restricted to captured desired-state/convergent setters which are safe
to reconcile. All other admitted commands return `Indeterminate`; caller/daemon recovery must
choose an explicit query/reconcile path. Tests must prove altered diagnostic strings do not affect
recovery, generic `Internal` errors do not recover, and worker death after execution/before reply
is never reported as a successful acknowledgement.

If P3 later adds a bounded queue, reserve capacity alone is insufficient. Shutdown/recovery needs
an out-of-band priority/cancellation lane plus a closing-admission bit: reject new normal commands,
service close before ordinary FIFO work, and resolve every already-admitted request. Add a full
normal-queue + shutdown/recovery test, alongside flood fairness, memory-cap, and no-duplicate
mutation tests. Deferring P3 remains correct while production retains one mutable backend owner.

**Adversarial evidence pointers.** Generic retry: `userspace_shared/mod.rs:267`; send-before-wait:
`userspace_shared/runtime.rs:727`; relay nonce/session/replay handling:
`rustynet-relay/src/transport.rs:326,340-376,467-470`; daemon keepalive:
`rustynetd/src/daemon.rs:6344`; relay send closure:
`rustynetd/src/relay_client.rs:705-729`; independent relay re-establish:
`rustynetd/src/daemon.rs:6941`; STUN candidate path:
`rustynetd/src/daemon.rs:5922-5963,6309+`; round-trip current-generation matching:
`userspace_shared/runtime.rs:986-1014`; relay ACK parsing:
`rustynetd/src/relay_client.rs:487-575,998-1030`. The reviewer made no edits or test claims.

**Relay recovery state-machine deep dive (2026-08-17; source + protocol research, design only).**
The ambiguity is now traced end to end. `RelayClient` consumes a pre-issued token artifact before
sending its hello (`relay_client.rs:169-228,487-552`); the userspace worker sends a round-trip
datagram before recording its response waiter (`userspace_shared/runtime.rs:695-745`); generic
`with_runtime_recovery` then recreates the runtime and replays the same payload
(`userspace_shared/mod.rs:267-283,568-583`; macOS parity at
`userspace_shared_macos/mod.rs:281-297,659-674`). The relay durably records the nonce before it
allocates a session (`rustynet-relay/src/transport.rs:326-376`), and current 19-byte hello ACK
carries only `session_id` + `allocated_port` (`relay_client.rs:998-1030`). Thus a lost ACK has an
exactly-once/at-least-once boundary: client cannot know whether the first hello committed, while a
late old ACK is indistinguishable from an ACK for a newer pending hello from the same relay address.

Two scope corrections matter. A fresh accepted hello for the same ordered node pair removes the
previous server session (`transport.rs:347,829-844`), and the relay's following inactive-allocation
prune aborts/removes the old port task (`main.rs:649-670,850-906`). No persistent allocation leak
is claimed. Conversely, server tuple binding has no socket-incarnation concept: first ciphertext
binds a session to a source tuple, later keepalive accepts that exact tuple, and a replacement
socket that happens to reuse it is indistinguishable to the relay
(`transport.rs:560-590,635-647`). A changed mapped port fails tuple validation. Rustynet must not
infer continuity from either outcome. Also, the client keepalive comment saying relay "should echo
or acknowledge" is stale: production relay consumes the 5-byte keepalive silently and sends no
ACK (`relay_client.rs:686-731`; `rustynet-relay/src/main.rs:781-786`).

**Recommended first contract — explicit recovery, not server idempotency.** Split current generic
recovery into one daemon-owned recovery coordinator, not a desired-state path and a hidden
protocol-I/O path. No `TunnelBackend` operation may recreate the runtime implicitly. Every caller
of current `with_runtime_recovery` returns typed `WorkerUnavailable` without a second operation;
the coordinator first quarantines traversal/relay state, then invokes a new
`recover_authoritative_transport()` which performs only socket/runtime reconstruction and returns
`Known(TransportIncarnation)`. It subsequently drives one high-level desired-state reconcile where
that is safe. This makes a worker loss during a path sample, handshake query, or configuration call
as visible as a loss during relay I/O. Authoritative round trips and sends never replay payload
merely because recovery occurred. Generic `Internal` remains non-retryable. Audit every current
`with_runtime_recovery` caller before changing it: `initiate_peer_handshake` is also a network send
and cannot be silently grouped with local desired-state setters without a separate proof.

The daemon transition is:

```text
RelayActive(I0)
  -- authoritative I/O reports worker loss --> Indeterminate / quiesced
  -- close local relay sessions; suppress old candidates and keepalives --> Recovering
  -- recover_authoritative_transport() --> SocketReady(I1)
  -- fresh relay hello + fresh token --> RelayActive(I1)
  -- fresh STUN transaction (independent, parallel) --> candidates for I1
```

`RelayClientSession` must retain the incarnation that created it. No selected relay endpoint or
client `last_activity` update survives the `Indeterminate` transition. Relay registration begins
as soon as `I1` exists; STUN re-probe/publishing proceeds independently and may fail without
blocking relay fallback. The backend may restore encrypted WireGuard desired state while the daemon
keeps old traversal/relay observations quarantined. Status must show old/new incarnation,
transition reason/time/count, relay state (`quiesced`, `registering`, `active`), candidate
freshness, and fresh matching-token inventory. This is an implementation contract, not a new IPC
fault-control surface.

**Relay wire change required for correctness.** Reuse the existing 16-byte, unique signed relay
token nonce as the client attempt correlation value: include it in `RelayHelloAck`, and require an
exact match to the hello's token nonce before the client records a session. Keep source-address
checking. This rejects a delayed ACK from a prior fresh-token attempt, but it does **not**
authenticate the ACK; nonce echo is visible to any observer of the hello. ACK origin
authentication needs separately distributed relay signing/MAC key material and is out of scope for
the first recovery fix. Do not make the nonce replay store implicitly idempotent in this slice: it
currently survives relay restart while sessions/allocated ports do not. Returning an old ACK merely
because a durable nonce is known could point a recovered client to a dead allocation. A future
idempotent-hello design must atomically retain canonical request digest, live session/allocation
state, and semantically equivalent ACK response, with restart behavior explicitly defined.

This matches established reliability practice. AWS recommends caller-provided request identifiers
and semantically equivalent retry responses only where a server can bind identity, parameters, and
outcome atomically ([AWS idempotent APIs](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/)). That invariant is absent here, so explicit recovery is safer.
STUN provides the contrasting safe pattern: responses echo a 96-bit transaction ID; a client checks
it before accepting a response ([RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489)). After
an unproven socket rollover, issuing a fresh STUN transaction ID is a conservative Rustynet
inference, not a claim that RFC 8489 forbids retransmission when the numeric local address is
unchanged.

**Token-inventory contract.** Local signing can mint a new token after an indeterminate hello.
Pre-issued mode intentionally deletes an artifact before send, so ACK loss spends a valid artifact
whether or not the relay committed. It is secure/fail-closed but can turn one worker loss into a
relay outage if no matching fresh token remains. Report matching usable-token count and earliest
expiry per `(node, peer, relay)` tuple, plus a low-watermark/replenishment alarm. Before automatic
re-establishment, attempt an actual atomic issue/claim and fail closed if it cannot obtain a fresh
artifact; a directory count is advisory because scan/expiry/removal are not a reservation protocol.
If operations requires a guaranteed recovery reserve, design a durable atomic claim/lease protocol
first. Otherwise leave relay unavailable with an explicit
`token_inventory_exhausted_after_indeterminate_hello` status. Do not reuse the consumed artifact
or silently switch to daemon-local signing, which is deliberately mutually exclusive with
pre-issued mode.

**Required deterministic test matrix before implementation closes.** Linux and macOS each need:

1. Worker death before command dequeue; no hello sent; recovery produces `I1`; fresh hello works.
2. Worker death after first hello send but before reply; relay accepts first hello, ACK is held;
   caller receives indeterminate, never automatic duplicate; a fresh-token hello replaces it.
3. Delayed ACK from attempt N arrives while N+1 waits; nonce mismatch rejects it; matching N+1 ACK
   alone installs endpoint/session `I1`.
4. Same-port and changed-port rebind paths; old session is never locally trusted; fresh registration
   succeeds and the old relay allocation is pruned.
5. One-way keepalive interrupted mid-send; no `last_activity` success record, no old-session retry,
   then re-register. STUN loss in the same transition cannot block relay re-registration.
6. Pre-issued token inventory 0/1/reserve: artifact consumption, low-watermark status, explicit
   depletion error, no reuse; local-signer parity. Relay restart during the sequence cannot make a
   nonce-only old ACK valid.
7. Worker death during `peer_latest_handshake_unix` or path-quality query; coordinator quarantine
   reaches `I1` before any later relay/STUN I/O on both OS implementations.
8. ACK-delivered active relay then relay process restart while worker remains `I0`; local UDP
   keepalive send alone cannot retain `active`, bounded liveness confirmation triggers re-register.
9. Old/new client × old/new relay wire matrix: strict 19-byte legacy parser remains safe, while
   negotiated new protocol requires nonce-matched hello ACK and confirmed keepalive response.

Add a loop/property test that interleaves delayed packets, worker death, identical local port reuse,
and daemon ticks; assert at most one locally selected relay session per peer/incarnation and no
accepted ACK without the pending attempt nonce. Run parity tests under both userspace backends,
then only a separately designed `--node` lab stage can establish NAT/relay behavior outside test
harnesses.

**Second adversarial review — two P0 corrections (2026-08-17; read-only source review).** The
first state machine was still too narrow: `with_runtime_recovery` wraps non-authoritative
`peer_latest_handshake_unix` and `peer_path_quality` calls on both Linux and macOS, while daemon
path-quality polling runs before relay work. A worker loss in one of those queries can recreate the
socket, reuse its port, and leave old relay/STUN state live before the next keepalive. The revised
single coordinator contract above is mandatory: *all* backend recovery first returns a typed loss;
daemon quarantine consumes it; only then may controlled runtime recovery create `I1` or any later
operation run. A per-operation receipt is insufficient if another recovery path can run first.
Add both-OS fault tests for worker exit during handshake/path query, asserting `I1` event, no old
candidate publication, and zero old-session keepalive before re-registration.

Relay restart is an independent P0. Relay nonce storage may persist, but sessions and allocated
sockets are process memory. After an ACK-delivered session, relay restart can erase the allocation
while the client remains on `I0`; a UDP `send_to` keepalive still succeeds locally and current code
updates client `last_activity`, even though the restarted relay silently drops it. Session refresh
is otherwise driven near token expiry. Nonce echo prevents a stale ACK from selecting an old
session; it does not prove an established allocation still exists. Split client timestamps into
`last_sent` and `last_confirmed`. Introduce a versioned, bounded relay-liveness probe/ACK which the
relay sends only after a valid currently bound session tuple; require its session ID + fresh probe
nonce + current incarnation before updating confirmed liveness. Missed confirmation transitions
`active -> suspect -> quiesced`, then fresh-token registration, with configured bounded backoff.
Relayed authenticated ciphertext can count as positive liveness only when it maps to the current
session/incarnation. Never treat local UDP send success as relay liveness.

The ACK/keepalive changes require an explicit rollout design. Existing hello ACK parser rejects any
length other than 19 bytes and server emits exactly 19 bytes; appending a nonce would break old
clients. Advertise an authenticated relay-protocol version/capability through signed fleet/control
metadata (or a separately versioned hello/ACK message), then test old/new client × old/new relay.
New recovery correctness must be enabled only for negotiated new protocol; legacy mode is
`unconfirmed` and must not falsely claim the stronger recovery/liveness guarantee. The token spool
counter is likewise observability only: `read_dir` + validation + delete has no durable reservation
semantic. Actual issue must atomically claim one artifact and fail closed; a guaranteed reserve
needs its own durable claim/lease design, including crash behavior.

**Second-review evidence pointers.** Hidden query recovery: Linux
`userspace_shared/mod.rs:462-583`, macOS `userspace_shared_macos/mod.rs:552-675`; daemon polling
before relay work: `rustynetd/src/daemon.rs:6344,6523-6533,6848-6871`. Relay runtime cleanup:
`rustynet-relay/src/transport.rs:194-256`, `rustynet-relay/src/main.rs:514-529`; silent local-send
keepalive/accounting: `rustynetd/src/relay_client.rs:705-729`,
`rustynetd/src/daemon.rs:6398-6439`; default token refresh: `daemon.rs:251-254,6933-6938`.
Rollout wire strictness: `relay_client.rs:998-1030`, `rustynet-relay/src/main.rs:701-706`.
The reviewer cleared no-generic-retry, nonce echo as correlation-not-authentication, tuple
conservatism, STUN/relay independence, no nonce-store idempotence without durable session state,
and Linux/macOS held-ACK parity tests. Reviewer made no code/test changes.

**Implementation blueprint — transport failure ownership (2026-08-17; proposed contract,
not yet implemented).** This is deliberately more prescriptive than the findings above so that
an implementation cannot accidentally reintroduce a hidden retry through a different backend
method.

1. In `crates/rustynet-backend-api/src/lib.rs`, add
   `BackendErrorKind::WorkerUnavailable` plus `BackendError::worker_unavailable(...)`. It means
   *an operation may not have run, may have sent a datagram, or may have mutated runtime state; its
   result is indeterminate*. It is not a synonym for `Internal`, and callers must switch on the
   enum rather than current Linux/macOS message-substring helpers. Audit exhaustive `match` sites
   in both platforms and any UI/status conversion.
2. Add `TransportIncarnation` to `AuthoritativeTransportIdentity`, represented as
   `Known(u64)` or `Unobservable`. `Known` is allocated on **every** authoritative socket creation
   (including initial backend start); a changed known value following explicit recovery denotes a
   replacement. It is not derived from IP/port/label. `Unobservable` is a capability result, not
   a change notification: receipt of `Unobservable` never itself causes re-registration. Preserve
   `local_addr` and `label` for diagnostics; equality of either is never evidence that incarnation
   stayed the same.
3. Add `TunnelBackend::recover_authoritative_transport(&mut self) ->
   Result<AuthoritativeTransportIdentity, BackendError>`. Its default returns fail-closed
   `Internal`/unsupported. Only shared-userspace backends implement it. It rejects a healthy,
   unlatched runtime with `AlreadyRunning` (or an explicit no-change receipt); it must never make
   an I1 socket merely because a caller asked. When fault-latched it reconstructs runtime and
   reapplies already captured backend desired state; it must not transmit relay/STUN protocol
   frames, invoke daemon callbacks, or replay an operation closure. `Phase10Controller` and the
   `DaemonBackend` match arms forward this method beside their existing authoritative
   identity/round-trip/send forwarding (`phase10.rs:6315-6339`; `daemon.rs:3327-3414`).
4. Replace Linux and macOS `with_runtime_recovery` with a non-retrying dispatch helper plus a
   **failure latch**. On detected worker loss, set the latch before returning
   `WorkerUnavailable`; while latched, *every backend call which dispatches work to the runtime*
   returns that same typed error without touching a socket or calling `ensure_runtime_control`. This includes configuration,
   peer endpoint/status/quality/handshake operations, routes, exit state, authoritative send and
   authoritative round trip. `recover_authoritative_transport` is sole operation allowed to clear
   latch, and only after it has returned new `Known(I1)` successfully. A failed recovery retains
   latch. This is stronger than "remember to catch errors in relay code": it makes a missed daemon
   call site fail closed instead of silently performing I/O on an unobserved replacement socket.
5. Change current worker-exit paths to create `WorkerUnavailable` at source. In particular,
   request-channel disconnection, reply-channel loss after worker exit,
   `fail_outstanding_round_trip`, and every error which makes the worker return from its
   authoritative-socket/TUN/timer polling loop must retain this kind plus causal text rather than
   manufacture the current platform-specific `Internal` strings
   (`userspace_shared/runtime.rs:1151-1184`; macOS parity `runtime.rs:1296-1329`). Remove
   `is_runtime_worker_unavailable` string classification only after all producers/tests use the
   enum. A malformed relay packet, timeout, rejection, or a per-request send error which leaves
   the worker alive remains its own error and must not trigger socket recovery. The criterion is
   worker survival, not whether the immediate source happened to be socket/TUN I/O.

**Daemon coordinator — exact ordering and operation classes.** `DaemonRuntime`, not
`RelayClient`, must own the one recovery gate because `sync_traversal_runtime_state` first calls
path-quality polling, then touches sessions/keepalives, while relay establishment is later in the
same tick (`daemon.rs:6344-6445,6917-6994`). Introduce one private coordinator, for example
`handle_authoritative_transport_fault(op, backend_error)`, reached immediately whenever a
`WorkerUnavailable` escapes a controller operation. Do not convert this error to a string:
`RelayClientError::AuthoritativeTransport(String)` must become a variant carrying `BackendError`,
and closure sites at `daemon.rs:6409-6414,6968-6973` must preserve it until coordinator dispatch.

Required algorithm, serialized by existing mutable daemon ownership:

```text
0. Recognize only BackendErrorKind::WorkerUnavailable. All other errors keep current policy.
1. Capture prior identity/status once; increment failure metric and record operation class.
2. Quarantine before any recovery call:
   close every local RelayClient session; clear relay keepalive/probe state;
   suppress relay endpoint selection; remove I0 STUN observations/candidates from publication;
   mark traversal statuses "transport_indeterminate". Do not send an old keepalive.
3. Call controller.recover_authoritative_transport() exactly once for this fault episode.
   Failure leaves traversal quiesced and returns an operator-visible retry/backoff result.
4. Validate returned Known(I1) differs from prior Known(I0). If Unobservable is supported for a
   backend, use explicit successful recovery event as the transition; never synthesize rollover
   from status polling. Store I1 once for this daemon tick/status snapshot.
5. Verify that recovery replayed staged backend desired state exactly once; do **not** issue a
   second backend reconcile from the daemon. Then schedule daemon traversal reconciliation: fresh
   relay registration with a fresh token and fresh STUN transaction(s) independently. Neither
   waits for the other. Do not resume candidate publication or endpoint selection until artifacts
   are tagged I1.
6. Resolve caller by operation class; never retry original protocol payload:
   * RelayHello / relay liveness round trip / authoritative send / WireGuard handshake send:
     report Indeterminate and let fresh high-level reconciliation decide later.
   * Read-only peer query: return unavailable for this tick; next scheduled poll uses I1.
   * Captured, convergent desired-state setter: run only once through post-recovery reconcile,
     never by rerunning original closure; report its final result separately.
```

Replace the current optional `authoritative_transport_identity(&self) -> Option<_>` status API
with a daemon-visible `AuthoritativeTransportState`, preferably
`Ready(identity) | Faulted { prior_identity, since } | Unsupported { blocker }`; it must never
silently map a latched fault to `None`, because `None` currently also means unsupported. This is a
read-only coordinator/backend snapshot, not a runtime-dispatch operation, so it remains available
while the latch blocks I/O. Capture it once when rendering status; current repeated identity reads
can otherwise render mutually inconsistent fields during a transition. Status and metrics must
include prior/current incarnation, fault operation, recovery count/time, relay quiesce reason,
stale-artifact count, and token inventory. The coordinator must run before later traversal code in
the tick. `poll_path_quality` therefore cannot swallow a worker-unavailable result; it must
surface it to the gate. A backend failure latch still protects the invariant if a future call site
is missed.

**Desired-state staging rule.** Current shared-backend desired maps are updated after a successful
runtime reply (`userspace_shared/mod.rs:462-467,470-485,521-539`; macOS parity), which loses
intent when the worker executes a convergent mutation then dies before its reply. Before enqueue,
validate pure input and stage convergent desired intent in a separate desired-state record (or
write the existing desired map before dispatch with a reversible definite-error path). On
`WorkerUnavailable`, retain staged intent; recovery replays that staged record once. On a definite
pre-admission/validation error, roll it back. Do not label any other ambiguous failure successful.
The daemon's post-recovery work verifies this one replay and rebuilds traversal state only; it does
not invoke the same backend mutation a second time. This rule applies to peer config/endpoints,
routes and exit state, but never turns relay hello, keepalive/probe, or handshake send into
desired-state work.

**Implementation blueprint — relay session state and v2 messages.** Replace
`RelayClientSession.last_activity` (`relay_client.rs:73-96`) with distinct evidence. Minimum
fields are: `transport_incarnation`, negotiated `wire_version`, `state` (`Establishing`, `Active`,
`Suspect`, `Quiesced`), `last_datagram_sent`, `last_relay_confirmed`, and optional
`pending_probe { nonce, sent_at, deadline }`. A current-incarnation, nonce-matched relay liveness
ACK is the primary confirmation. Authenticated ciphertext can update `last_relay_confirmed` only
when implementation can prove it maps to this selected session and incarnation. A fresh peer
handshake timestamp alone is not enough evidence, so the current unconditional
`relay_client.touch_session()` for relay-selected peers (`daemon.rs:6358-6367`) must not become a
substitute for relay liveness.

Reserve protocol codes `0x11..=0x14`; do not append to strict v1 formats:

```text
0x11 RelayHelloV2       = same canonical signed-token hello body as v1, new type byte
0x12 RelayHelloAckV2    = type | session_id[16] | allocated_port_be[2] | token_nonce[16]  (35 B)
0x13 RelayProbeV2       = type | session_id[16] | probe_nonce[16]                         (33 B)
0x14 RelayProbeAckV2    = type | session_id[16] | probe_nonce[16]                         (33 B)
```

`RelayHelloAck`/serialization in `rustynet-relay/src/transport.rs` and `main.rs` must carry the
accepted token nonce. Client retains issued token nonce until result handling, requires exact
source address, exact v2 message length, non-zero session/port, and exact nonce before installing
session. A prior-attempt ACK therefore cannot satisfy current attempt. This is request-response
correlation, **not relay authentication**: retain existing source filtering; do not claim secrecy
or integrity from an echoed nonce. V1 stays exactly 19 bytes (`0x02 | session_id | port`) and v1
parsers must reject every v2 frame/length as they do today.

**Critical D3 demux rule for probes.** Do **not** target allocated relay port through current
generic `authoritative_transport_round_trip`. That port is installed as WireGuard peer endpoint
(`RelayClientSession::effective_endpoint`, `relay_client.rs:237-244`; daemon programming around
`daemon.rs:6604-6605`), so runtime correctly rejects it
(`userspace_shared/runtime.rs:976-984`, macOS parity). Relaxing that rejection would be worse:
the current generic waiter consumes every datagram from its remote before WireGuard processing
(`runtime.rs:867-905,986-1014`), so peer ciphertext could be stolen by a control waiter.

V2 therefore requires a new **narrow backend-owned multiplexed-control capability**, not a
generic exception or caller-supplied response predicate. Add a typed
`AuthoritativeControlKind::RelayLivenessV2` request with target, 33-byte `0x13` probe and its
complete expected 33-byte `0x14 | session_id | probe_nonce` ACK. Only this kind may target a
configured peer endpoint. In both runtime implementations, an outstanding probe delivers a
datagram only when all conditions hold: same remote address, same socket generation, exact
33-byte length, `0x14` discriminator, and constant-time/full byte equality to the precomputed
expected ACK. Every non-match continues to `engine.process_inbound_ciphertext`; no packet is
dropped merely because it came from a relay peer endpoint. Keep generic round-trip peer-endpoint
rejection unchanged. The API must not accept an arbitrary callback/prefix supplied by daemon code;
that would recreate the interception primitive this design excludes.

This probe still goes to allocated relay port, so it exercises/control-refreshes that NAT mapping
and the live allocation task. Add allocated-port task handling for `0x13`: authorize tuple, then
send exact `0x14` ACK from the same allocated-port socket. It must not be handled on relay control
port: under endpoint-dependent NAT, a control-port probe can have a different mapped tuple and
does not prove allocated-port liveness. The exact random nonce means a WireGuard frame or malformed
packet cannot be accepted as a probe response; it instead reaches normal engine processing.

Permit one pending probe per session, cap one synchronous probe per daemon traversal tick, and set
a short bounded deadline in configuration. On timeout, wrong source, wrong length, wrong session
ID, or wrong nonce, do not update confirmation. Transition `Active -> Suspect`; after configured
bounded consecutive misses, `Suspect -> Quiesced`, delete local session, and schedule a fresh-token
registration with backoff. Local `send_to` success updates only `last_datagram_sent`; it never
confirms allocation or resets miss count. This replaces the stale "relay should echo" comment and
the current success-driven `last_activity` update (`relay_client.rs:686-729`).

Relay handling for a probe must use an explicit `authorize_probe_from_tuple`, not make
`touch_session_from_tuple` silently weaker. It accepts only a live, unexpired session and either
the exact bound tuple or, when unbound, the same-IP first-tuple rule already used for first
ciphertext (`transport.rs:560-590,635-647`); in the latter case it records that tuple before ACK.
Any other tuple/session/expired frame is silently dropped. Respond at most once per accepted
probe; ACK equals request length, and no error response is emitted. This avoids a response
amplifier and preserves current source-binding threshold. After relay restart there is no live
session, so no ACK: client cannot mistake local outbound UDP success for liveness.

**Rollout and control-plane contract.** Current signed relay-fleet format is strictly
`version=1`: parser rejects any other version and any unknown key; descriptor has only
`relay_id, region, endpoint, priority, capacity, enabled`
(`rustynet-control/src/lib.rs:1456-1532,4060-4260`). It cannot safely carry an optional v2 bit.
Do **not** mutate a v1 signed payload in place or publish fleet v2 to old clients: old daemons
will fail closed on their sole traversal bundle.

Recommended zero-outage path: add a separate, same-trust-root signed relay-capabilities bundle.
Its canonical, versioned payload binds each `relay_id` **and exact endpoint** to a bounded sorted
set of supported relay wire versions and normal generated/expiry/nonce/signature fields. New
daemon verifies both the existing fleet membership and capability binding before V2 use; absent,
expired, invalid, or non-intersecting capability means V1 only. Old daemon ignores the separate
artifact and continues its verified v1 fleet. Deploy in strict order:

1. Ship new relay binary supporting v1 and v2, but advertise only v1.
2. Ship new daemon/control parser with v1 fallback and full parser/canonicalization tests.
3. Publish short-lived signed capability records for verified v2 relays; confirm every selected
   endpoint maps to its record before enabling v2 there.
4. Enable V2 per relay. New clients negotiate highest common version; old clients keep v1.
5. Expose `legacy_unconfirmed` for v1. Do not advertise v2 recovery/liveness guarantees there.
6. Retire v1 only after fleet telemetry proves no legacy clients, using explicit maintenance policy.

A single relay-fleet v2 format remains possible only as an announced breaking migration after all
clients can parse it. It is not this fix's default. Capability data, v2 hello, and probe behavior
must be feature-gated together; sending `0x11` merely because a client was upgraded is forbidden.

**Token and relay-restart semantics.** Add inventory reporting keyed by `(node, peer, relay)`:
eligible count, earliest expiry, observation time, and low-watermark. Label scans advisory.
`PreissuedRelaySessionTokenIssuer::issue_token` is the real claim point because it validates then
removes its matching artifact before transmission. Do not treat a file count as a reserve. A
guaranteed reserve needs separately designed atomic move/lease, durable outcome record, fsync and
crash-reaper semantics; do not smuggle it into this recovery change. For an indeterminate hello,
do not reuse its artifact; ask issuer for a new one or remain quiesced with precise depletion
status. Do not call local signing fallback from pre-issued mode.

Never add nonce-only server idempotency here. Durable nonce storage outlives process-memory
sessions/allocation tasks, so replaying stored ACK after restart can return a dead port. A future
idempotent hello requires one atomic durable record containing nonce, canonical request digest,
session/allocation lifecycle, response, and explicit restart semantics. V2 probe is required even
after ACK delivery because restart can erase all allocations while client socket stays I0.

**Required test hooks and acceptance gates.** Existing `RuntimeTestState` only counts worker exit
(`userspace_shared/runtime.rs:1073-1085`; macOS `1218-1230`); add deterministic fault points,
not timing sleeps: `BeforeCommandDequeue`, `AfterCommandDequeueBeforeSend`, and
`AfterDatagramSendBeforeReplyOrWaiter`. The last point proves actual hello delivery followed by an
indeterminate client outcome. Implement equivalent hooks/parity assertions in both userspace
backends. Keep fault injection test-only and fail worker through normal cleanup/error paths.

Required named test groups before merge:

1. `backend_api`: every exhaustive `BackendErrorKind` conversion recognizes
   `WorkerUnavailable`; shared backend latches, rejects all operation families, recovers only by
   explicit method, then reports I1; Linux/macOS parity. Generic round-trip to a configured peer
   endpoint remains rejected. While a typed V2 probe is outstanding at that endpoint, a real or
   synthetic WireGuard ciphertext datagram and every wrong-length/wrong-nonce `0x14` frame reaches
   normal engine processing; only byte-for-byte expected ACK completes control request.
2. `daemon`: query-induced worker loss reaches coordinator before keepalive; assert no I0 relay
   send, no I0 candidate publication, relay registration starts before/without successful STUN;
   status snapshot records one coherent transition.
3. `relay_client`: v1 exact 19-byte compatibility; v2 exact-size parsing; held ACK N rejected
   while N+1 pending; source/session/nonce mismatch rejected; local send never increases confirmed
   liveness; one outstanding probe limit and timeout state transitions.
4. `rustynet-relay`: probe exact-bound success; first same-IP probe binding success; different-IP
   and expired/unknown session silent drop; one response no larger than request; v1 behavior
   untouched. Test accepted hello then process restart then local I0 probe receives no ACK.
5. End-to-end deterministic sequence: accept hello, drop ACK, kill worker after send, recover I1,
   establish fresh-token session; inject stale ACK; restart relay after a confirmed session; require
   bounded quiesce/re-registration. Run Linux and macOS shared backends, both pre-issued and local
   issuer modes. Assert no duplicate local selected session for `(peer, incarnation)`.
6. `rustynet-control` capability bundle: canonical sort, duplicate/unknown field rejection,
   signature failure, expiry, relay ID/endpoint mismatch, absent fallback V1, and rollout matrix
   old/new client × v1/v2 relay. Test a v1 parser still rejects v2 fleet payload, proving staged
   rollout assumption rather than accidentally relying on compatibility.

Merge order: typed failure/latch + coordinator tests first; then v2 server/client parser tests;
then signed capability artifact; then enabled rollout. P3 command queue work remains separate:
it must not land inside this P0/P1 reliability change.

**Third adversarial review — blueprint corrections incorporated (2026-08-17; read-only,
no code/test changes).** The first blueprint incorrectly sent V2 probe through generic
`authoritative_transport_round_trip` to allocated relay port. That port is exactly the configured
WireGuard peer endpoint, and runtime rightly refuses generic round trips there; worse, generic
response delivery runs before ciphertext demux and would consume arbitrary datagrams from the
peer. The corrected blueprint above keeps that rejection, specifies an exact-ACK,
backend-owned `RelayLivenessV2` multiplexer, and requires a regression proving interleaved peer
ciphertext remains with the WireGuard engine. A control-port-only probe was rejected too: on
endpoint-dependent NAT it can prove a different mapping, not live allocated-port forwarding.

The review also found four contract details now resolved above. (1) Errors in authoritative socket,
TUN, or timer polling currently terminate worker; if an error causes that exit, it must surface
`WorkerUnavailable` with cause and latch, rather than masquerade as ordinary socket I/O. (2) Current
identity API returns `Option`, so it cannot represent a typed latched fault; status now requires
`Ready | Faulted | Unsupported` rather than silently mapping fault to unsupported. (3) Current
desired maps mutate only after replies, so recovery cannot replay a mutation whose worker reply was
lost; convergent desired intent must be staged before enqueue and replayed once. (4) socket
generation is assigned at every socket creation, including initial startup; recovery must reject a
healthy/unlatched request so it cannot create a new incarnation before daemon quarantine.

**Third-review evidence pointers.** Peer endpoint selected from relay session:
`rustynetd/src/relay_client.rs:237-244`; daemon applies it around `daemon.rs:6604-6605`; generic
round-trip rejection: `userspace_shared/runtime.rs:976-984` and macOS parity; pre-engine generic
response dispatch: `runtime.rs:867-905,986-1014`; terminal worker polling paths:
`runtime.rs:1151-1184`, macOS `1296-1329`; optional identity API:
`backend-api/src/lib.rs:260-265`, controller `phase10.rs:6315-6317`; post-reply desired map
updates: Linux `userspace_shared/mod.rs:462-539`, macOS parity; generation allocation:
`userspace_shared/socket.rs:20,51-55` and macOS `socket.rs:21,56-60`. Reviewer made no source
edits and did not run tests.

**Focused baseline recheck (2026-08-17, no new implementation).** Passed:
`cargo test -p rustynet-relay --lib --locked test_replayed_nonce_rejected` (one-use relay nonce);
`cargo test -p rustynetd --lib --locked
preissued_relay_session_token_issuer_consumes_matching_signed_token` (artifact is deleted before
the transport send); and `cargo test -p rustynet-backend-wireguard --lib --all-features --locked
linux_userspace_shared_backend_relay_round_trip_and_send_use_same_transport_generation_as_peer_path`
(peer, relay round trip, and relay send share one generation). These are source-contract baselines,
not proof of the proposed worker-loss/held-ACK state machine. No product code or new test changed.

**Recheck evidence (2026-08-17, `dea73a75`).** `cargo test -p
rustynet-backend-wireguard --lib --all-features --locked transport_generation` passed 5 focused
tests, including Linux/macOS generation rollover and Linux same-generation peer/STUN/relay proof.
Both daemon worker-exit recovery tests pass under `cargo test -p rustynetd --lib --all-features
--locked`, one exact test each for Linux and macOS. No live-lab claim follows from these unit and
test-harness checks.

### QH-55 — a failed dataplane apply degrades into a silent 1-second retry loop

Cluster of observability defects around `restrict_recoverable`, live-observed during the QH-53
diagnosis: (i) after `DEFAULT_MAX_RECONCILE_FAILURES = 5` the restriction promotes to Permanent
(daemon.rs:9645-9652) and `restrict_recoverable` becomes a silent no-op (9613-9616) while the
FailClosed leg keeps retrying every second with no log of its own (9476-9483); (ii)
`refresh_signed_state_with_reason` RESETS `reconcile_failures` (daemon.rs:5077), un-promoting
the permanence and restarting the silent cycle; (iii) the pre-expiry refresh scheduler
self-disables once the on-disk traversal bundle goes stale (hints cleared to None,
daemon.rs:4968-4976), so "signed state refresh completed" lines simply stop; (iv) `run_daemon`
logs "runtime bootstrap complete" unconditionally after a FAILED bootstrap
(daemon.rs:10380-10381). Together: a wedged node looks quiet, not broken. Fix direction:
bounded, LOUD retries (`resilience.rs` policy per its adoption rule), a terminal
operator-visible state, and an honest bootstrap-outcome log line.

**FIXED 2026-08-21 (observability; fail-closed posture unchanged).** All four defects, one
increment in `crates/rustynetd/src/daemon.rs`: (i) `restrict_recoverable`'s Permanent
early-return is no longer silent — it eprintlns the new failure ("node already PERMANENTLY
restricted; new failure while restricted: …") and refreshes `bootstrap_error`, so the 1-second
FailClosed retry loop stays operator-visible while the mode itself remains Permanent
(fail-closed preserved); (ii) the refresh success tail was extracted into
`complete_verified_signed_refresh`, which REFUSES to reset anything when
`restriction_mode == Permanent` (loud eprintln, counters preserved) — a successful signed-state
FETCH alone can no longer un-promote permanence; honest recovery still only happens through the
reconcile success arm (real dataplane apply); (iii) `traversal_next_preexpiry_refresh_target`
now falls back to `Some(now_unix)` when `traversal_hints` are None but
`traversal_hint_error` is recorded, so a stale bundle no longer silently disables the pre-expiry
refresh scheduler — attempts resume, still bounded by `MIN_TRAVERSAL_REFRESH_COOLDOWN_SECS`;
(iv) `run_daemon` logs "runtime bootstrap complete (restricted: <error>)" when
`bootstrap_error` is set instead of an unconditional success line. Deliberately NOT done here:
a resilience.rs backoff loop for the reconcile retry — the existing per-second FailClosed retry
is pre-existing behavior and now loud; changing its cadence is a behavioural change out of this
item's observability scope. Five unit tests pin each behavior
(`restrict_recoverable_under_permanent_keeps_mode_and_records_new_failure`,
`complete_verified_signed_refresh_preserves_permanent_restriction`,
`complete_verified_signed_refresh_clears_recoverable_restriction`,
`preexpiry_refresh_target_stays_scheduled_after_hint_clear`,
`promote_to_permanent_threshold_unchanged`). Mutation-proven: silencing restrict_recoverable,
deleting the Permanent guard, deleting the scheduler fallback, and weakening the promotion
threshold (`>=`→`>`) each flipped exactly its pin test red; restored → 5/5 green. Not yet
live-proven on a lab guest.

**[[QH-46]] enforcement-test closure (2026-08-14).** The §4 gap the handover flagged is closed:
`ensure_host_firewall_admits_forwarding` and its `allow_tunnel_relay_forward` gate now carry a
cross-platform source-pin test (`linux_firewall_apply_checks_host_firewall_when_forwarding`,
IPV-10 pattern), seven `cfg(linux)` behavioural tests through the real helper protocol (fail
closed on unbound / unparseable / unknown-binding / builtin-error postures; pass on bound /
absent; a plain client never drives the builtin), an operation-order assertion on
`relay_with_upstream_enables_tunnel_forwarding_path`, and five helper-side boundary tests
(grammar incl. zone-token rejection — the zone stays unrepresentable — builtin classification,
binary-resolution refusal, token round-trip). Mutation-proven on BOTH platforms: macOS caught
delete-call, gut-check, remove-gate, controller-reorder; the Debian guest caught swallow-Err,
missing-bound-as-clear, hardcoded-interface, and Bind→Query. All 14 tests pass on the guest.
Residual, deliberate: the D-Bus executor `execute_linux_firewalld_zone` itself remains
live-lab-only coverage.

### QH-56 — five live-lab stages still hardcode the `debian` SSH username

Run `qh53-liveproof-20260815a`: `live_enrollment_restart_validation`, reached for the first time
once the QH-46/QH-53 fixes unblocked the cascade, failed dialing `debian@192.168.64.105`
(rocky-utm-1, user `rocky`). [[QH-49]]'s fix introduced `resolve_ssh_user` (inventory username
first, platform fallback) but left it private to the LAN-toggle stage.

**Corrected sweep (the first filing overstated):** of the five `_ => "debian"` matches, three —
`stage/chaos.rs`, `stage/cross_network.rs`, `stage/live_anchor.rs` — are the FALLBACK arm of a
correct `params.user.unwrap_or_else(default_ssh_user(...))` pattern and were never broken. The
genuinely broken sites, which ignored the inventory entirely, were exactly two:
`stage/live_enrollment_restart_validation.rs:135` and
`stage/live_mixed_topology_validation.rs:158`.

**FIXED 2026-08-15:** `resolve_ssh_user` hoisted into `stage/mod.rs` (QH-49 doc and trimming
semantics preserved), both broken sites now consult the inventory username, the LAN-toggle stage
imports the shared helper, and its unit tests exercise the shared symbol. The three
fallback-correct stages keep their own `default_ssh_user` values untouched — their
"administrator"/"admin" defaults differ from the LAN-toggle's, and changing an untested fallback
is a separate behavioural change. Helper is unit-proven; the call-site wiring is proven live by
the next run reaching `live_enrollment_restart_validation` with a `rocky@` dial (same proof shape
QH-49 used).

### QH-57 — the LAN-toggle stage saws off the branch it sits on, and the bad state persists

Run `qh56-enrollment-20260815b`: `live_lan_toggle_validation` moved the client's management CIDR
to the toggle LAN (`192.168.18.0/24`); the full-tunnel management bypass followed; every
host↔guest packet then routed into the tunnel (`ip route get 192.168.64.1` → `dev rustynet0
table 51820`, proven live), including the stage's OWN SSH session, which died mid-toggle. The
toggle-back never ran and the toggle-LAN CIDR persisted in signed state across daemon restarts
and a full power cycle (g3→g7). Cleanup could not reach the client; recovery required
out-of-band `utmctl exec` (stop the daemon, drop the `ip rule`).

Two sub-defects: (1) the stage's transition plan has no reachability continuity — the management
set must cover BOTH LANs for the transition window, or the toggle must be driven over a
toggle-immune path; (2) nothing bounds a management-CIDR assignment whose LAN never appears —
the daemon faithfully re-derives the dead bypass forever. Fix needs the full plan + adversarial
review cycle; the fail-closed posture itself behaved correctly and must not be weakened.

### QH-58 — Cross Platform CI was red for months on ten independent test-hermeticity defects

Main's CI had not been fully green since 2026-03-03 — five and a half months. Investigated
2026-08-15 across all legs; ten distinct causes, all fixed the same day (commits
`bf84290c`..`767b32a3`):

1. **The `/tmp` sweep (both macOS victims).** One test's marker file lived directly in
   `temp_dir()`, and `cleanup_temp_path` removes the marker's PARENT — an error-swallowed
   `remove_dir_all` of the entire shared temp namespace, latent since 2026-05-25. It randomly
   destroyed other tests' uniquely-named fixtures mid-run: on GH macOS runners the near-
   deterministic nextest schedule landed the sweep window on `transition_local_utm_vm_accepts_
   timeout_when_vm_reaches_stopped_state` or `rust_native_reuse_seal_rejects_modified_stage_log`
   (wall-clock overlap proven in three runs' logs), and on ubuntu-kvm-1 it killed a discovery
   test's inventory mid-read. Fixed: marker in its own unique dir; `cleanup_temp_path` AND
   `cleanup_temp_inventory` now fail closed (assert) on a temp-dir-rooted parent —
   mutation-proven (a root-level marker panics the sweeping test with the guard's message).
2. **CRLF vs `include_str!` (Windows, deterministic since 2026-07-30).** The relay clock source
   pin's LF-joined needle never matched a CRLF checkout. Fixed: normalize before searching, plus
   `.gitattributes` forcing LF for `*.rs` so every source pin is checkout-invariant.
3. **Ephemeral port inside the default dataplane range (Windows, ~61% flake since 2026-07-28).**
   The relay control-packet test probed a port from the OS dynamic range, which overlaps the
   default 50000-59999 dataplane range; `validate()` rejects the config, and Windows's
   sequential allocator made all 16 retries fail together. Fixed: the test pins the range to
   1024-5119.
4. **Machine identity baked into a fixture (ubuntu-kvm-1 only).** The hosts-declaration test
   used the real ubuntu-kvm-1 record, and `resolved_connect_uri` deliberately collapses to
   `qemu:///system` on that very host. Fixed: synthetic host_id + RFC 6761 `.invalid` hostname.
5. **`safe.directory` discarded by the MCP git tools' hardened env (Debian container).**
   `GIT_CONFIG_GLOBAL=/dev/null` also dropped the CI checkout's dubious-ownership exemption
   (git honors `safe.directory` only from system/global config FILES); every read-only git tool
   died in the uid-mismatched container — masked until the QH-46-era clippy failure was fixed.
   Fixed: the hardened env points at a minimal owned config containing only `safe.directory=*`,
   keeping all other isolation.

6. **Runner-independent Linux probes asserted empty (Debian, unmasked next).** The sysinfo
   every-tool-unavailable test asserted empty interfaces and DNS resolvers — but on Linux
   `observe_interfaces` reads `/sys/class/net` and `observe_dns` reads `/etc/resolv.conf` by
   design. Could never pass on Linux; expectations now cfg-split, tool-driven asserts unchanged.
7. **Root runner takes the root arm (Debian container, unmasked next).** The local-peer
   authorization test asserted the socket-owner arm, but a root peer legitimately authorizes
   via the preceding root arm. The sibling denial test was already root-guarded; the allows
   test now asserts the arm actually taken in each environment.
8. **The custody round-trip pair was BORN FAILING (all Linux).** The credential-only passphrase
   control (`2dc39fca`, 2026-03-04) refuses a configured direct path unless
   `RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH`/`CREDENTIALS_DIRECTORY` names the source, and
   the unsafe-forbid workspace means no test can set env — so the two daemon custody tests
   (added 2026-04-02 and 2026-07-23) never once passed on Linux: cfg'd off macOS where
   development runs, module excluded on Windows, and fail-fast masking upstream on Debian.
   Fixed with a `cfg(test)` thread-local credential-path override consulted at the same
   decision point the env variable feeds — non-test builds byte-identical, every downstream
   check unchanged, and the tests now exercise the exact production decrypt chain in the
   explicit-credential mode systemd uses.

9. **Self-written "untrusted" fixtures are root-owned under a root runner (two twins).** The
   symlink-to-untrusted-target tests in key_material and phase10 write their own target, so a
   root runner makes it root-owned and the must-be-root-owned rejection can never fire (the
   privileged_helper sibling was already root-guarded). Fixed by chowning the fixture to nobody
   when root — the same rejection asserts in every environment.
10. **The socket poll-budget test raced datagram arrival (macOS, rare flake).** It sent
   budget+3 datagrams over real loopback and asserted the FIRST poll ingested exactly the
   budget; arrival is not synchronous with send_to. Now polls until drained, asserting the
   per-poll cap on every iteration plus at least one capped poll.

**PROVEN GREEN: run 31898492213 (2026-08-15, commit `767b32a3`) — all four legs success.**

The masking structure is why this looked like one bug: nextest is fail-fast, so each leg showed
only its first victim; compile-stage failures (the `type_complexity` lint) hid the test layer
entirely; and per-OS cfg gates hid Linux-only breakage from macOS development. **The last fully
green Cross Platform CI run was 2026-03-03 — the day before the custody control landed.** Every
fix keeps the original assertions' meaning intact; none weakens a fail-closed control.

### QH-59 — FIXED: the overnight executor's group kill was broken or catastrophic on Ubuntu

`spawn_with_timeout`/`spawn_capture_with_timeout` killed a timed-out agent's process group with
`kill -KILL -<pgid>` — no `--`. Ubuntu 24.04's procps `kill` parses the bare negative as its
FIRST DIGIT (`-12345` → `kill(-1?2345…)` → `-1`): a wedged tree either survives the timeout
(non-1 leading digit, exit 0, nothing killed) or, with a leading-1 pgid, becomes
`kill(-1, SIGKILL)` — SIGKILL to every process the user may signal, empirically confirmed via
strace in an ubuntu:24.04 container. Debian's and macOS's kill parse the bare form correctly,
which is why CI never caught it; the box's full-suite failures (three "parallelism" tests) were
collateral of this blast. Fixed with `--` before the pgid (verified on all three platforms);
the wedged-process test on the box went from days-red to a 1.0s pass.

**QH-57 FIXED (2026-08-16) — with two corrections to the original filing.** The management CIDR
was never signed state: it travels stage → `e2e-enforce-host --ssh-allow-cidrs` →
`/etc/default/rustynetd` (`RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS`, carried forward on every
reinstall by `env_string_or_existing_default`) → daemon flag; the signed artifact in the wedge
was only the full-tunnel assignment. And the client died during "Enforcing runtime roles" —
before any LAN toggling — the moment full-tunnel policy routing engaged with a bypass list
containing only the stale CIDR. The stale value's source was the test binary's hardcoded
default `192.168.18.0/24` (the bash-era lab LAN), which the stage wrapper never overrode even
though the orchestrator auto-derives the correct per-run CIDRs and the two_hop stage already
threads them. The stage had never completed its assertions on the `--node` engine: 0 pass /
475 skip / 12 fail in 487 recorded rows.

The fix threads `ctx.ssh_allow_cidrs` through the stage with two_hop's entry validation,
removes the default from the binary (required flag + choke-point validation rejecting empty,
default-route entries, and overlap with the synthetic `LAN_TEST_CIDR`), and sweeps the class:
the reboot-recovery binary's identical default is gone (its nested two-hop subcheck enforces
the value; its wrapper now threads ctx), the extended soak's `0.0.0.0/0` fallback is a
fail-closed error, and the managed-dns wrapper threads the real value instead of an inertly
hardcoded `0.0.0.0/0`. Validation helpers are unit-tested; mutations (restore either default,
gut either validation, restore the soak fallback) are all caught. Sub-defect (1) — transition
reachability continuity — is thereby resolved for the real failure mode: the enforced CIDR now
IS the live LAN. The dormant out-of-band channel (`LIVE_LAB_ENABLE_UTM_TRANSPORT`,
live_lab_support/mod.rs:125-160) is noted as the recovery-channel option for any future stage
that must genuinely move a node off its management LAN. Live proof: the next run must carry
the client through role enforcement with SSH intact and reach the stage's eight checks — a
first for the `--node` engine.

### QH-60 — nothing validates a management CIDR against live interface addressing

Sub-defect (2) of [[QH-57]], now its own item: the daemon accepts a management CIDR covering
none of its interfaces — `ManagementCidr::FromStr` checks only syntax and bounded-operator-range
containment, `validate_daemon_config` only non-emptiness, and the bypass route pins the
configured egress interface without checking the CIDR is on-link. A wrong-but-plausible CIDR
therefore silently disconnects management on any full-tunnel node (QH-57's exact failure,
minus the stale-default source, which is fixed). Attach-point candidates from the
investigation: the `FromStr` choke point all three backends funnel through (phase10.rs:189),
or an on-link/FIB probe at apply time via `resolve_route_interface_for_ip` (phase10.rs:1130).
Security-design change: refusing a config narrows management access (fail-closed direction),
but the refusal semantics on nodes with legitimately off-link management (cross-network
topologies!) need the full plan + adversarial review cycle before any code.

**QH-60 CLOSED (2026-08-19).** Full plan + adversarial review cycle completed (design doc in
session scratchpad; three-lens investigation + review with two blocking amendments applied).
Shape landed: an apply-time anchoring check in `apply_fail_closed_management_bypass_routes`
(phase10.rs `ensure_management_bypass_anchored`), not a `FromStr` change — the parser stays
pure and the check runs where the environment-dependent fact lives. A management CIDR is
ANCHORED iff it overlaps a connected IPv4 prefix on the egress interface (overlap, not
contains-an-address, so a /32 admin-workstation pin inside the on-link /24 anchors); observed
via the privileged helper (`ip -4 -o addr show dev <egress>`, two new read-only argv arms with
the interface-name guard). If no CIDR anchors AND the apply's exit mode is FullTunnel (plumbed
via a new non-defaulted `set_full_tunnel_engaged` trait method, DryRun-asserted), the apply
refuses BEFORE the table-51820 rule engages — QH-57's byte-for-byte scenario becomes a loud,
recoverable red (the reconcile loop retries) instead of a self-cut SSH. Under Off, unanchored
entries warn and install (refusal would brick mesh-join for exit-less nodes). IPv6 entries are
excluded from the quorum while IPv6 parity is off; an all-v6 list refuses under full-tunnel.
Observation failure (spawn error or non-zero exit) fails closed. Same change-set: the boot
parser `BootSshCidr::parse` now applies `validate_mesh_egress_source_cidr`, closing the /0
split-brain where the boot rule installed an unrestricted port-22 accept and the daemon then
exited InvalidConfig leaving it live; a drift pin asserts the boot parser rejects what the
daemon parser rejects. Evidence: commits `70e22434` + `3aca4c16`; 28 targeted tests green on
Linux (debian-headless-4) and all macOS-runnable ones locally; full `rustynetd` suite 2053/2053
on Linux, 2260/0 locally (`--all-targets --all-features`); clippy `-D warnings` clean. Mutation
matrix all CAUGHT (7/7): delete the check call, neuter the overlap predicate, remove the
FullTunnel gate, swallow the observation error (each fails its Linux test); drop the controller
plumbing (DryRun wiring assertion fails), delete the argv arms (validator pin fails — added
because the scripted-helper harness bypasses `validate_ip_args`), drop the boot alignment
(drift pin fails). The cross-network off-link concern from the original entry dissolved under
investigation: the bypass route is emitted dev-only (no `via`), so gateway-routed management
never worked through this mechanism, and the cross-network shared list always contains each
node's own /24 — refusal costs no working topology. macOS/Windows have no equivalent wedge
(management survival rides pf/WFP rules, not policy routes) — documented, not implemented.
Live proof rides the next green-lit run: every full-tunnel node exercises the check on each
generation apply. Follow-up filed as [[QH-62]] (Windows installer drops `-SshAllowCidrs`).

### QH-62 — Windows installer validates then discards `-SshAllowCidrs`

Found by the QH-60 investigation (lens B claim 2): the Windows installer declares and
validates an `-SshAllowCidrs` parameter, then never threads it into the installed service
environment — the operator's input is silently discarded. Windows management survival rides
WFP rules rather than the Linux policy-routing bypass, so this is not a QH-57-shaped wedge,
but a validated-then-dropped operator input is a defect regardless: either thread it to the
WFP management allow (parity with the Linux env pair) or remove the parameter and document
why. Needs the Windows installer + `rustynet-windows-native` WFP surface read before choosing.

**FIXED 2026-08-21 (threaded, not removed).** The daemon side already supported the pair on
Windows — `daemon.rs` builds `WindowsCommandSystem` with
`.with_fail_closed_ssh_allow(config.fail_closed_ssh_allow, config.fail_closed_ssh_allow_cidrs)`
and phase10's `apply_windows_scoped_egress_allows` emits scoped WFP netsh allows for those
CIDRs under the killswitch (the same semantic as the Linux/macOS SSH_ALLOW_CIDRS env pair).
The gap was purely installer plumbing. Fix: `Install-RustyNetWindowsService.ps1` gains an
optional `-SshAllowCidrs` param with its own fail-closed charset validator
(`Test-RustyNetSshAllowCidrs`, mirroring the wrapper's `Assert-SshAllowCidrs`) and threads it
through `Write-ReviewedEnvFile` → `Build-ReviewedDaemonArgsJson`, which emits the MATCHED pair
`--fail-closed-ssh-allow true --fail-closed-ssh-allow-cidrs <cidrs>` only when non-empty
(allow=true alone trips the daemon's config validation, so the pair is atomic); empty emits
neither flag, preserving every existing caller byte-for-byte. The e2e wrapper
`rn_bootstrap_windows.ps1` forwards its validated value on the final authoritative install-helper
invocation. Removal was not viable: the vm_lab source pins require the wrapper's
`Assert-SshAllowCidrs` line, and callers outside this fix's lane pass the parameter. Two source-pin
tests in `install/live_windows.rs` (`install_helper_threads_ssh_allow_cidrs_into_the_daemon_args_env`,
`bootstrap_wrapper_forwards_ssh_allow_cidrs_to_the_install_helper`) pin param + validator-before-consume +
matched-pair-after-empty-guard + both forward sites; mutation-proven (deleting the wrapper forward and
the daemon-args pair each fails exactly its own test). Not yet live-proven on a Windows guest — the
first bootstrap that passes a non-empty `-SshAllowCidrs` exercises it end-to-end.

### QH-61 — bare `rustynet` argv heads die under sudo on RHEL-family guests

Run `qh57-lantoggle-20260816a` (the QH-57 live proof: client survived role enforcement with SSH
intact for the first time; 40 passes, a run record): the LAN-toggle stage's next layer was
`sudo: rustynet: command not found` on rocky-utm-1. Rocky's `secure_path` is
`/sbin:/bin:/usr/sbin:/usr/bin` — no `/usr/local/bin` — so any bare `rustynet` argv head run
via `sudo -n sh -lc` fails on RHEL-family guests while Debian masks the trap. Proven live: the
binary exists at `/usr/local/bin/rustynet`, the user shell resolves it, sudo does not. The
LAN-toggle binary is fixed (all 15 sites → the shared `REMOTE_RUSTYNET_BIN`); the SAME bare
shape remains in seven other stage binaries, latent until a role lands on a non-Debian guest:
`live_linux_anchor_test.rs`, `live_linux_enrollment_restart_test.rs`,
`live_linux_reboot_recovery_test.rs`, `live_linux_server_ip_bypass_test.rs`,
`live_linux_network_flap_test.rs`, `live_linux_control_surface_exposure_test.rs`,
`live_linux_endpoint_hijack_test.rs` (plus `collect_network_discovery_info.rs`, non-sudo).
Sweep them file-by-file (each needs import and shape care), mirroring the LAN-toggle commit.

**QH-61 SWEEP COMPLETE (2026-08-17).** All seven sibling binaries plus `collect_network_discovery_info`
now use `REMOTE_RUSTYNET_BIN` — 37 production sites across eight files (the anchor test's two
fake-shell test invocations deliberately untouched). A source pin in `live_lab_support`
(`stage_binaries_never_spawn_rustynet_by_bare_name`) scans every stage binary's production
half for the banned shape with a runtime-assembled needle; mutation-proven (reintroducing one
bare head names the offending file). The lab live-proved the mechanism on run 44 (lan_toggle
pass after the same fix); the siblings inherit it by construction and are unit-locked, not
separately live-proven — each will be exercised the first time its role lands on a Fedora/Rocky
guest.

## ADVERSARIAL REVIEW SWEEP — sec-hardening branch (2026-08-23)

Manager-agent sweep of rustynet-control / rustynet-policy / rustynet-crypto test and
fix surfaces. Six production fixes plus companion tests; every fix mutation-proven
(revert → test fails → restore). Branch `sec-hardening`, all scoped gates green
(fmt / clippy -D warnings / 567+ tests across the three crates).

- `00165bb8` role_audit reader accepted UNKNOWN fields (invisible to the canonical
  hash) and DUPLICATE keys (last-write-wins) on otherwise-valid lines — both now
  rejected fail closed. Test: `reader_rejects_unknown_and_duplicate_fields_on_valid_lines`.
- `f83ac54a` TamperEvidentAuditLog::append now returns Result and rejects `|`,
  `\n`, `\r` in actor/action: newlines injected forged `entry=` lines that
  backup+restore faithfully accepted; pipes shifted fields into an unrestorable
  log. Test: `append_rejects_delimiters_that_would_inject_or_shift_entries`.
- `a018036c` + `b6254a66` redaction needles broadened (`passwd`, `api_key`,
  `apikey`, `authorization`, `auth_header`) and separators canonicalized
  (`-`→`_`) so kebab-case keys like `private-key` hit the snake_case needles.
  Tests: `redaction_covers_common_secret_key_and_value_shapes`,
  `redaction_covers_kebab_case_secret_key_variants`.
- `c241ee42` scheme matching accepts tab after `bearer`/`basic` (header folding).
  Test case folded into the common-shapes test.
- `44f3848c` scale.rs `authorize_trusted_key` fingerprint compare switched to
  constant-time `ct_eq` (RSA-0016 standard); behavioral regression covered by the
  pre-existing missing/mismatch/match test.
- `127ff20d` EnterpriseAuthConfig::validate_claims rejects empty/whitespace OIDC
  subjects (`InvalidSubject`). Test:
  `enterprise_auth_rejects_empty_subject_claims`.
- `5150f169` HaCluster::mark_unhealthy clears a stale active pointer when the
  ACTIVE replica dies, so callers polling active_replica() cannot route to a dead
  node. Test: `marking_active_replica_unhealthy_clears_stale_active_pointer`.

Companion pins landed alongside: policy empty-set/no-rules/CIDR-literal/composite-
selector semantics, crypto seed-determinism + label-independence + zero/FF/1KB/4KB/
100KB size matrix + provider-policy matrix, key_rotation unfrozen-past-epoch +
canonical-payload exactness, membership spoofed-id/empty-roster/rollback, role-audit
replay/gensis/genesis-binding/non-monotonic/corrupt-hash, role-presets lockout pins.

### Second-wave companion pins (same sweep, post-ledger additions)

- ga: deprecation calendar exact boundaries fail closed (`>=` at both
  `deprecates_at_unix`/`removal_at_unix`; off-by-one mutation-proven).
- ga: `lifecycle_for` returns Denied when the CALENDAR itself fails validation
  (inverted window) rather than consulting broken records.
- ga: release gate reports each unmet condition specifically — all seven
  conditions flip-tested from green; misreported variants caught.
- ga: performance budget enforces each of six thresholds independently
  (at-limit passes, +0.01 over any single limit fails).
- scale: `elect_active` breaks generation ties by lowest replica id regardless
  of insertion order (deterministic leader choice across restarts).
- key_rotation: bundles tagged with an UNFROZEN past epoch fail closed as
  UnknownEpoch (`advance_to` records no rotation points); archive canonical
  payload pinned byte-exact including count header and per-verifier fields.
- persistence: group/other-readable `-wal` SIDECAR fails open() closed like the
  main DB file (RSA-0017 sidecar arm previously unpinned).
- crypto: signature binds to seed+payload only — key_identifier never perturbs
  signature bytes; provider-policy acceptance matrix (hardware-primary,
  software-primary-ok, local-fallback-forbidden) pinned.
