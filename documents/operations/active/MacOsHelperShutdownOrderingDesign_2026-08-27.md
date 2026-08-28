# QH-40 / D-7 — macOS privileged-helper shutdown ordering and fail-closed rollback reporting — design — 2026-08-27

**Status: DESIGN. Half implemented on `work/d7-qh40-helper-order` (§1 — the fail-closed
reporting), half BLOCKED ON OWNER SIGN-OFF (§2, §3 — anything that changes the privileged
helper's lifetime or the teardown sequence).** Written against base `main` @ `876f298f`.

Every claim below was produced by reading the code in this worktree, and the file:line is
given so a reviewer re-runs rather than trusts. Where a claim comes from a live-lab log I
could not re-query (this task had no lab access), it is labelled as such and NOT relied on.

Supersedes the remedy in [`QH40ShutdownRollbackPlan_2026-08-11.md`](./QH40ShutdownRollbackPlan_2026-08-11.md),
which was itself marked **REVIEWED AND REFUTED**. That document's refutation note is the
best prior art here and most of it survives scrutiny; §4 below records which parts of it I
could confirm and which I could not.

---

## 0. The three questions, answered in the order the ledger asks for

| # | Question | Answer |
| --- | --- | --- |
| 3 | Should the daemon refuse to report `exit(0)` when rollback failed? | **Yes, and the exit code is the weaker half.** Implemented: a durable, never-auto-cleared residue marker plus `ExitCode::PolicyReject` (78). §1. |
| 1 | Is the ordering fixed or racy? | **Both, depending on the path.** The *signal* order is deterministic and correct everywhere (daemon first). The *completion* order is racy on two paths and deterministically wrong on two others. §2. |
| 2 | Should the helper outlive the daemon by design? | **Yes — and launchd cannot express it.** There is no `After=`/`Requires=` equivalent for LaunchDaemons, so ordering must be enforced by the callers and by a lease inside the helper. §3. Deferred to sign-off. |

---

## 1. Question 3 — the fail-closed question (IMPLEMENTED)

### 1.1 The defect, confirmed in code

`Phase10Controller::shutdown` (`crates/rustynetd/src/phase10.rs:6553`) does its job: it
accumulates every teardown failure, transitions the dataplane to `FailClosed`, and returns
the error (`phase10.rs:6569-6572`). Both callers then threw it away.

* Unix signal gate — `crates/rustynetd/src/daemon.rs:10942-10948` (pre-change): logged the
  error as `(best-effort)` and `break`, falling through to
  `scrub_runtime_wireguard_key_after_bootstrap(&config)?; Ok(())` at `daemon.rs:11204-11205`.
  `main.rs`'s error path (`main.rs:88-96`) is a *startup* path and never ran, so the process
  exited **0**.
* Windows SCM gate — `daemon.rs:10720-10731`: same shape, with an explicit and *correct*
  reason for staying at exit 0 (a non-zero service exit makes the SCM refuse the next start).

### 1.2 What a non-zero exit actually buys under launchd — the constraint that shapes the design

`KeepAlive` is `true` **unconditionally** (not `SuccessfulExit`) in both the reference plist
(`scripts/launchd/com.rustynet.daemon.plist:57-58`) and the plist the installer renders
(`scripts/bootstrap/macos/Install-RustyNetMacosService.sh:436-438`). Two consequences, and
they point in opposite directions:

1. **A non-zero exit cannot create a restart loop that `exit(0)` was not already creating.**
   launchd restarts an unconditional-`KeepAlive` job on *every* exit. The exit code changes
   the log line and nothing else — including nothing about the 10 s respawn throttle. So the
   change is **risk-free on availability**, which is why it is in the implemented half.
2. **For exactly the same reason it is nearly inert as a signal.** Nothing on the macOS path
   reads the daemon's exit code: the only `daemon_exit_code` consumer in the tree is
   Windows-only. An exit code is a channel only if something reads it, and on macOS nothing
   does.

So "exit non-zero" is necessary but **not sufficient**. Residue must be impossible to miss
by launchd *and* by the live-lab evidence pipeline; the exit code addresses neither.

### 1.3 The chosen design — a durable marker as the primary channel

New module `crates/rustynetd/src/shutdown_residue.rs`:

* **Durable file, written the instant the failure is known** — before anything else can go
  wrong, because launchd will `SIGKILL` shortly after `SIGTERM` (see §4.3). Path is a sibling
  of the daemon state file, `<state>.shutdown-residue.json`, so it inherits the state
  directory's already-validated ownership and permissions. `0600` on Unix — the rollback
  error text names interfaces and addresses, and the macOS state directory is group-readable
  by `rustynetd`.
* **Its own `schema_version`**, so it costs **no** change to the daemon's persisted-state
  schema. This was the blocking objection in the prior plan (`persist_state` writes only
  `{timestamp_unix, peer_ids, selected_exit_node, lan_access_enabled}`,
  `daemon.rs:9126-9132`); a separate file with a separate schema retires it.
* **Written atomically** (temp sibling + rename) so a crash mid-write cannot leave a truncated
  marker that later reads as "undecodable" for the wrong reason.
* **Never cleared automatically.** Not on daemon start, not on a successful later shutdown.
  The only removal path is the explicit operator acknowledgement in §1.5. An automatic clear
  would let the very restart launchd performs erase the only durable evidence.
* **Undecodable counts as residue.** `ResidueScan::Unreadable` is a distinct variant, not a
  discardable `Err`, and `is_residue()` answers `true` for it. A marker we cannot parse is
  residue evidence we failed to decode — treating it as clean would recreate the exact
  silent-success defect this module closes (AGENTS.md §3). Same for an unknown future
  `schema_version`.

### 1.4 Wiring, and the two ordering constraints that shaped it

* **Unix signal gate** records the marker, stores the message, and returns
  `DaemonError::ShutdownRollbackResidue` **after the loop**, not at the shutdown site.
  *This ordering is load-bearing:* returning at the shutdown site would skip
  `scrub_runtime_wireguard_key_after_bootstrap`, leaving plaintext WireGuard key material at
  rest — an AGENTS.md §4 key-custody violation *created by the fix*. This was the third
  refutation of the prior plan's C2 and it is honoured here.
* **Windows SCM gate** records the marker and keeps its clean stop, deliberately. Its existing
  comment is right: a non-zero service exit makes the SCM refuse the next start. On Windows
  the marker is therefore the **only** loud channel, which is another reason the marker rather
  than the exit code is the primary mechanism.
* **`main.rs` banner.** The residue error is the one `DaemonError` that is not a startup
  failure. Printing `rustynetd startup failed` for it sent operators to the wrong half of the
  lifecycle, so the banner is selected off a pinned token,
  `SHUTDOWN_RESIDUE_FAIL_CLOSED_TOKEN = "shutdown rollback failed (fail-closed)"`. Because
  that token contains `fail-closed`, the pre-existing `classify_top_level_error`
  (`main.rs:100-130`) already buckets it as `ExitCode::PolicyReject` — **78**, whose operator
  hint is `DO NOT retry without operator review` (`exit_codes.rs`). No new taxonomy entry was
  needed; a test pins the coupling so a reword cannot silently drop it to `GenericFailure`.

### 1.5 Surfacing to the orchestrator

New read-only, unprivileged CLI:

```
rustynetd shutdown-residue-check --state <path> [--acknowledge]
```

* clean → prints the scanned path, exits **0**
* residue → returns the fail-closed message, exits **78**
* `--acknowledge` → the ONLY path that removes a marker; prints what it cleared

This exists because the evidence pipeline reads *probe exit codes over SSH*, which it already
does for every other `*-check` command — that is a channel it actually consumes, unlike a
launchd exit code. `validate_baseline_runtime` (`adapter/ssh.rs:584-589`) is the natural
place to add it; **that wiring is NOT in this change** (see §5).

Startup additionally scans and logs under a stable grep token
`shutdown_rollback_residue_detected` (`daemon.rs`, immediately after config/ACL validation),
so a log scrape finds it even with no probe wired.

### 1.6 The disposition question — why startup REPORTS rather than REFUSES

The brief proposed "a persisted residue marker file the next start refuses to proceed past".
I implemented detect-and-report and am flagging the refusal as the sign-off decision, for a
reason that I think inverts the intuition:

**Refusing to start does not remove the residue.** A start *applies* dataplane state; it does
not roll back. So a refusal trades a silently-residual host for a **crash-looping host
carrying exactly the same residue** — under `KeepAlive = true` that is a permanent 10 s
respawn loop with no operator escape short of hand-deleting a file. That is louder, but it is
not more secure, and AGENTS.md §2 asks for the strictest *practical* default.

The genuinely strictest option is not "refuse" but **"re-run the teardown at startup, and
refuse to proceed into normal service until it succeeds"** — which is a real fail-closed
posture because it actually clears the residue. That touches the privileged path and the
controller lifecycle, so it belongs with §3 behind sign-off. Recorded here as the recommended
escalation, deliberately not taken unilaterally.

**A note on scope honesty:** with report-only, residue is impossible to miss *by an operator
or a probe* (durable file + 78 + grep token), but a node that reboots unattended still comes
back up carrying it. That gap closes only with the §3 work.

---

## 2. Question 1 — is the ordering fixed or racy?

**Answer: the signal order is deterministic and already correct; the completion order is not,
and two paths are deterministically wrong rather than racy.** Four teardown sites exist:

| Site | Order | Wait between daemon and helper | Verdict |
| --- | --- | --- | --- |
| `scripts/bootstrap/macos/Install-RustyNetMacosService.sh:545-552` | daemon, then helper | `sleep 1` | **RACY** |
| `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:753-760` | daemon, then helper | `sleep 1` | **RACY** |
| `crates/rustynet-cli/src/install/uninstall.rs:70-75` | daemon, then helper | **none** — a bare `for` loop over the two labels | **DETERMINISTICALLY WRONG** |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs:46-51` (`MACOS_LAUNCHD_STOP_COMMAND`) | daemon, then helper | **none** — back-to-back in one `;`-chain | **DETERMINISTICALLY WRONG** |

Two mechanisms, and it matters which one a reviewer reasons about:

1. **`launchctl bootout` is asynchronous.** It returns once the `SIGTERM` is sent, not once
   the job exits. So "boot the daemon out first" buys nothing on its own — the daemon is
   still running its rollback when the next line executes.
2. **Both shell sites then guess.** `sleep 1` is a fixed guess against a rollback whose
   duration is not bounded by anything in our control. The prior plan measured the daemon's
   graceful shutdown at **1.020 s** against that 1 s sleep — a 20 ms margin. I could not
   re-measure it (no lab access), and I would not build on that number regardless: the point
   is that a fixed sleep is racy *by construction*, not that 1.020 s is the true figure.
3. **The two Rust sites do not even guess.** `uninstall.rs` iterates the two labels with no
   delay at all, and `MACOS_LAUNCHD_STOP_COMMAND` — which the live-lab orchestrator runs on
   every macOS traffic-adapter stop (`macos_traffic.rs:432`) — chains them with `;`. On those
   paths the helper is signalled microseconds after the daemon, which is far inside any
   plausible rollback duration. **These are the paths a reviewer should look at first, and
   neither prior QH-40 document mentions them.**

**Two claims from the ledger entry that I could not confirm, and one I believe is wrong.**

* The ledger says launchd signalled the helper at `01:01:18.984` and the daemon at
  `01:01:18.985` — "the helper one millisecond earlier". The refutation note in
  `QH40ShutdownRollbackPlan_2026-08-11.md` §0 re-derives the same window with a bounded
  `log show` and reports the *daemon* signalled **1.019 s earlier**, arguing the ledger
  compared the helper's SIGTERM against the daemon's *exit*. **The code independently
  supports the refutation**: all four sites above boot the daemon out first, two of them with
  explicit comments saying why. I could not re-run the log query, so I am not asserting the
  timeline — but a reviewer should treat the ledger's "helper 1 ms earlier" as **contradicted
  by the repository's own code and by its own follow-up document**, and the D-7 brief inherits
  that claim from the stale ledger text. See §6.
* System **reboot/shutdown** is a fifth path and it is unconditionally racy: launchd signals
  its daemons without any ordering we can express (§3.1). No code change to our scripts
  affects it.

---

## 3. Question 2 — should the helper outlive the daemon? (DEFERRED — SIGN-OFF REQUIRED)

**Yes, plainly: the daemon's entire shutdown rollback is privileged work it can only do
through the helper.** The design question is *how*, and it has one hard constraint.

### 3.1 launchd cannot express the dependency

There is no `After=` / `Requires=` / `PartOf=` equivalent for `LaunchDaemons`. The keys that
exist are per-job (`RunAtLoad`, `KeepAlive`, `ProcessType`, `ExitTimeOut`); nothing orders
one job's teardown against another's. This is why the repo already *simulates* the systemd
relationship in prose — `Install-RustyNetMacosService.sh:471-479` says the helper plist gives
macOS "the same `Requires=rustynetd-privileged-helper.service` semantics that systemd provides
implicitly", and `Bootstrap-RustyNetMacos.sh:752` says the teardown order "matches the systemd
`Requires=` teardown order". Both comments are honest about intent and both are unenforced.

**Therefore: there is no plist key to add.** The brief's escape hatch ("a plist ordering key
that launchd genuinely honors") does not exist, so nothing here qualifies as the small
unambiguous fix, and the helper-lifetime work stays behind sign-off.

### 3.2 Options, and the recommendation

**Option A — callers wait for the daemon to actually exit (bounded poll on
`launchctl print system/com.rustynet.daemon`), at all four sites.**
Strictly better than `sleep 1` (it waits for the event rather than guessing) and it is the
only option that helps `uninstall.rs` and `MACOS_LAUNCHD_STOP_COMMAND`, which today have no
wait at all. But the prior plan's C1 was refuted on a real point: the poll observes "job gone"
whether the daemon exited cleanly **or** was `SIGKILL`ed by launchd, so a naive poll reports
success for a killed rollback. **That objection is now answerable**: the §1 marker
distinguishes the two, so a poll paired with a residue check is sound where a poll alone was
not. The 30 s bound in the refuted plan is still wrong — the wait must be under launchd's own
kill ceiling (§4.3), so bound it there and treat a timeout as a finding printed on stdout.

**Option B — the helper refuses to exit while a rollback session is open (a lease).**
The daemon opens a short-lived, explicitly-scoped rollback lease before teardown and releases
it when rollback finishes or fails; the helper defers its own `SIGTERM` exit until the lease
closes or a bounded timeout elapses. This is the only option that survives the reboot path in
§2, because it needs no cooperation from whoever sent the signals.

**Privileged-boundary constraints on Option B (AGENTS.md §4), non-negotiable:**

* A lease must **not widen what the helper will do, or for whom**. Same argv-only exec, same
  strict validation, same allowlist, same peer-credential check (`--allowed-uid` /
  `--allowed-gid` are resolved at install time via `dscl` —
  `Install-RustyNetMacosService.sh:487-493`). A lease changes *when the helper exits*, nothing
  about *what it will execute*.
* The lease must be **bounded and self-releasing**. An unbounded lease is a privileged process
  that a compromised or wedged daemon can pin alive indefinitely — a strictly worse security
  posture than the bug being fixed.
* The bound must sit under launchd's kill ceiling (§4.3), or launchd resolves it for us with a
  `SIGKILL` and the lease was theatre.
* Only the already-authorised peer may hold a lease; a lease must not be acquirable by any
  caller the helper would otherwise reject.

**Recommendation for sign-off: Option A + Option B together**, with A first (it is mechanical
and covers the four scripted paths) and B second (it is the only thing that covers reboot).
Neither is implemented here.

### 3.3 A caveat that may make all of §3 the wrong fix

The refutation note in the prior plan argues the observed rollback failures are **not** an
ordering problem at all: it reports that the *first* rollback step failed with
`truncated frame header` while the helper was **still alive**, and that the same failure
appears on `bootstrap_apply_failed` and `membership_reconcile_failed` — paths with no teardown
in flight whatsoever.

**The code makes that mechanism concrete and plausible.** `--timeout-ms` is the *helper's own*
server-side I/O timeout; the daemon's help text records the default as 2000 ms
(`Install-RustyNetMacosService.sh:326`, matching
`privileged_helper.rs:64 DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS = 2_000`), and
`annotate_helper_response_read_error` (`privileged_helper.rs:660-685`) documents a live
observation on a 2-core guest of "a continuous `truncated frame header` loop that stopped dead
when the timeout was raised from 2000 ms to 10000 ms". The rendered helper plist sets
`--timeout-ms 30000` (`Install-RustyNetMacosService.sh:515-516`), so the deployed helper is
already at the raised value — which is itself worth checking against whichever build produced
the ledger's evidence.

**So sign-off should decide the ordering work and the timeout hypothesis together.** Landing
Option A/B against a failure actually caused by an I/O timeout would produce a green-looking
change that fixes nothing — which is exactly how the previous QH-40 remedy got refuted. The
§1 marker is deliberately independent of that question: it makes the failure *visible*
whatever its cause.

---

## 4. What I could and could not verify

### 4.1 Verified in code (re-runnable)

* `KeepAlive = true`, unconditional, both plists — `com.rustynet.daemon.plist:57-58`,
  `Install-RustyNetMacosService.sh:437-438`; helper plist likewise at `:520-521`.
* Neither plist declares `ExitTimeOut` — `grep -n ExitTimeOut scripts/launchd/* scripts/bootstrap/macos/*` returns nothing.
* Helper plist runs `--timeout-ms 30000` — `Install-RustyNetMacosService.sh:515-516`.
* Documented default 2000 ms, matching the Rust constant — `:326` and `privileged_helper.rs:64`.
* All four teardown sites, order and wait — table in §2.
* `Phase10Controller::shutdown` returns the accumulated error — `phase10.rs:6553-6578`.
* Both callers discarded it — `daemon.rs:10720-10731` and `:10942-10948` (pre-change).
* `ExitCode::PolicyReject == 78`, hint `DO NOT retry` — `exit_codes.rs`.
* `persist_state` writes four fields only — `daemon.rs:9126-9132`.

### 4.2 Inherited from the prior document, not re-verified here

The guest unified-log timeline in `QH40ShutdownRollbackPlan_2026-08-11.md` §0 (daemon
signalled 1.019 s *before* the helper; graceful shutdown measured at 1.020 s). This task had
no lab access. The code independently corroborates the *direction* (daemon first everywhere),
which is why §2 treats the ledger's "helper 1 ms earlier" as contradicted — but the exact
figures are not mine.

### 4.3 The kill ceiling — genuinely unresolved, and it bounds §3

The refuted plan quotes a launchd log line `scheduling cleanup in 5 sec after sending
Terminated: 15` and treats 5 s as the hard ceiling. I could not re-observe that line, and it
does not match the `ExitTimeOut` default I would expect from `launchd.plist(5)`. **Any wait or
lease bound in §3 must be re-measured on a live guest before it is chosen**, and must be set
below whichever value is real. Picking 30 s because the helper's `--timeout-ms` says 30000 —
as the refuted plan's C1 did — is exactly the mistake to avoid.

---

## 5. What is implemented on this branch vs. deferred

**Implemented (commit "Fail closed when macOS/Windows shutdown rollback leaves dataplane residue"):**

| Item | Location |
| --- | --- |
| Durable residue marker: type, atomic write, fail-closed scan, operator acknowledge | `crates/rustynetd/src/shutdown_residue.rs` (new) |
| Unix gate records marker; non-zero exit **after** the key scrub | `crates/rustynetd/src/daemon.rs` |
| Windows SCM gate records marker, keeps clean SCM stop | `crates/rustynetd/src/daemon.rs` |
| Startup detection + stable grep token, no auto-clear | `crates/rustynetd/src/daemon.rs` |
| `DaemonError::ShutdownRollbackResidue` → `PolicyReject` (78), shutdown-specific banner | `crates/rustynetd/src/daemon.rs`, `crates/rustynetd/src/main.rs` |
| `rustynetd shutdown-residue-check --state <path> [--acknowledge]` | `crates/rustynetd/src/main.rs` |
| 20 tests, incl. negative tests for undecodable marker, unknown schema, lost marker write, and the clean-shutdown exit-0 path | both files |

**Deferred — REQUIRES OWNER SIGN-OFF before implementation:**

1. **§3 helper lifetime** — Option A (bounded exit-wait at all four teardown sites) and/or
   Option B (bounded rollback lease inside the privileged helper). Privileged-boundary change.
2. **§1.6 startup disposition** — whether a residue marker makes the next start re-run the
   teardown and refuse normal service until it succeeds. Changes the availability semantics of
   every macOS and Windows node.
3. **§4.3** — re-measure launchd's actual post-`SIGTERM` kill ceiling on a live guest; it
   bounds every wait in (1).
4. **§3.3** — decide the helper-I/O-timeout hypothesis in the same review, so an ordering fix
   is not landed against a failure it does not cause.

**Deferred, no sign-off needed, just not in scope here:**

5. Wire `shutdown-residue-check` into `validate_baseline_runtime` (`adapter/ssh.rs:584-589`)
   so the run matrix carries the verdict. Note that evaluator's known weakness — it accepts
   any probe on a raw `"overall_ok": true` substring match, no schema check — recorded in the
   QH ledger just above the QH-40 entry; a new probe should not inherit it.

---

## 6. Ledger corrections this change makes

The QH-40 entry in `QualityHardeningTodo_2026-07-25.md` still states the mechanism as "launchd
SIGTERMs the privileged helper BEFORE the daemon". Per §2 that is contradicted by all four
teardown sites in this repository and by the repository's own follow-up document. The entry is
updated in place with the correction, the original claim left visible per this register's norm
on retracted findings, and a pointer to this document. **The D-7 brief that commissioned this
work inherits the same stale claim** — a reviewer reading only the brief will reason from a
mechanism the code does not support.

---

## 7. Definition of done

* §1 implemented end-to-end with an enforcement point and a verification test per control
  (AGENTS.md §4) — **done**, 20 tests including the required negative test.
* §7 gates green from this worktree — see the branch's gate record.
* §2/§3 carry explicit sign-off markers rather than TODOs in shipped code (AGENTS.md §3) —
  **done**: nothing half-built was left in the tree; the deferred work exists only as this
  document.
* QH-40 ledger entry updated with status and a pointer here — **done**.

---

## 8. QH-40-MEASURE verdict — 2026-08-27, live measurement on `macos-utm-1`

**Status: MEASURED IN PART, with the unmeasured half named precisely.** Lab access was
authorized for this task and used surgically on `macos-utm-1` (macOS 26.5, build 25F71,
arm64) over SSH. Two of the three measurements are settled; the reload-ordering matrix is
not, for a stated tooling reason, and nothing below pretends otherwise. Raw outputs are in
the appendix (§8.6) so a reader re-derives rather than trusts.

### 8.1 The kill ceiling (§4.3) — SETTLED: 5 seconds

`launchctl print` reports the effective per-service value directly; no induced shutdown was
needed:

| service | `exit timeout` |
| --- | --- |
| `system/com.rustynet.privileged-helper` | **5** |
| `system/com.rustynet.anchor` | 5 |
| `system/com.rustynet.exit` | 5 |
| `system/com.openssh.sshd` (Apple's own) | 5 |

No rustynet plist declares `ExitTimeOut` (§4.1), so these are launchd's default on macOS
26.5. The refuted plan's `scheduling cleanup in 5 sec` line is corroborated; §4.3 is
resolved. **Every wait or lease bound in §3 must sit under 5 s.** The helper's own
`--timeout-ms 30000` is 6× the ceiling — any helper work outstanding at SIGTERM+5 s dies by
SIGKILL regardless of what Option A/B negotiates.

### 8.2 The competing hypothesis (§3.3) — the stated mechanism is REFUTED; a third cause,
which both prior documents missed, fits the evidence

**Protocol fact (code, re-runnable).** `truncated frame header` is produced ONLY by
`UnexpectedEof` on the 10-byte header read (`map_read_exact_error`,
`privileged_helper.rs`). A client-side read timeout maps to a *different* string —
`read frame header failed: Resource temporarily unavailable (os error 35)`. So every
"truncated" observation in the ledger is, by construction, a server-side close that sent
**zero** response bytes. No timeout on the daemon's side of the socket can produce it.

**Live measurement 1 — the helper does NOT silently drop on its own I/O timeout.** A root
peer (root is an authorized peer, `privileged_helper.rs:548`) connected to the live helper
(pid 311, deployed `--timeout-ms 30000`, 2026-08-26 build) and sent nothing. The helper
held the idle connection **60.01 s** (= peek window + request-read window, 2 × 30000 ms),
then wrote a **well-formed** RNHF response frame (version 1, type 2, 79-byte payload
carrying `read frame header failed: Resource temporarily unavailable (os error 35)`) and
only then closed. Helper alive throughout, same pid. Repeated twice, 60.007 s and 60.012 s.
The daemon on this path receives the helper's error string — never `truncated frame
header`. The causal claim inside `annotate_helper_response_read_error`
(`privileged_helper.rs:660-685`) — timeout elapses → helper "drops the connection" →
truncation — is therefore **wrong on the current build**: every timeout path
(request-read timeout, and the `run_privileged_subprocess(timeout)` execution watchdog in
`handle_request_with_timeout`) returns a well-formed error response.

**The third cause, and it fits the 2026-08-11 signature exactly.** The helper has precisely
one close-without-response path: the **oversized-response silent drop**, documented at
`privileged_helper.rs:83-90` — a response exceeding the frame budget makes `write_frame`
refuse and the server `let _ = write_response(...)` drop the connection with no bytes,
while the helper stays alive. The un-clamped construction site named there is the pf-load
**failure** message — and the 08-11 evidence's FIRST truncated step was exactly a pf
rollback failure (`rollback dns protection: rollback failed: firewall apply failed`), seen
**while the helper was alive for another 1.019 s**. That message was only bounded at the
deliverability budget on **2026-08-25** (`64774bdd`) — *after every observation in the
ledger*. So the "truncated while alive" evidence attributes to a since-fixed response-size
defect, **not** to the helper's I/O timeout and **not** to signal ordering. The
`Connection refused` failures on the *later* rollback steps remain fully consistent with
the §2 completion race (the helper was booted out ~1 s after the daemon, mid-rollback).
The 2000→10000 ms live fix most plausibly worked by relaxing the execution watchdog
(slow commands on the 2-core guest stopped being killed at 2 s, so the failing —
and budget-blowing — error path stopped being taken); the annotation's wording should be
corrected, though its advice (name the knob) can stay.

**A real timeout defect neither prior document names.** The deployed daemon plist sets NO
`--privileged-helper-timeout-ms`, so the daemon's *client* timeout is the 2000 ms default
(`daemon.rs:2045`) while the helper *serves* with 30000 ms. Any privileged command slower
than 2 s fails on the daemon side (`os error 35`) even though the helper completes it —
and during shutdown such a failure is a rollback-step failure. This asymmetry should be
fixed alongside Option A: pass the daemon flag with the helper's value.

### 8.3 The reload-ordering matrix (measurement 1) — NOT MEASURED, and why

The live matrix (3–5 reloads × the four §2 call-site shapes, with pid sampling) required
bringing the daemon up on the guest. The daemon's killswitch is applied unconditionally on
dataplane apply (`phase10.rs:5565`) and default-denies all egress, so a daemon started
without the SSH allowlist severs the measurement session; this harness's permission
classifier denied every route to that configuration (writing the allowlist env, and
deploying/detaching the self-contained cycle driver). Rather than degrade the isolation
rules, the matrix was left unrun. The prepared driver (bootstrap → 13 teardown cycles
across `daemon_only` / `script_seq` / `no-wait` shapes × helper 30000/2000/10000 ms → pf
flush + restore) exists in the session scratchpad for an interactive operator to run.

What the retained unified log does show (14-day window): every recorded teardown
(2026-08-26 10:48, 10:56, 10:59, 11:22, 11:25) found the jobs already `service inactive`
at bootout — no `signaled service` ordering lines survive, and the 08-11 window has aged
out of retention. So §2's code-derived verdict (daemon-first signal order at all four
sites; completion race on the two shell sites; no wait at all on the two Rust sites)
stands **unmeasured but uncontradicted**, and the ledger's retracted "helper 1 ms earlier"
claim gains no new support.

### 8.4 The residue marker — no live firing (blocked as above), two negative-path observations

* An **unprivileged** `shutdown-residue-check --state /usr/local/var/rustynet/rustynetd.state`
  fails CLOSED against the 0700 state directory: `marker present but undecodable …
  Permission denied (os error 13) … treated as residue`, exit **78**. The fail-closed
  scan semantics of §1.3 behave as designed on a real guest.
* A **root** scan of the clean state directory reports clean, exit **0**.
* The guest's deployed 2026-08-26 daemon binary predates the marker (0 occurrences of
  `shutdown_rollback_residue_detected` in `strings`); a fresh build @ `4b0d18aa` (marker
  included) is now installed at `/usr/local/bin/rustynetd` on `macos-utm-1`, so the next
  induced failure there can fire it.

### 8.5 What this means for Option A's sign-off — RE-SCOPE

1. **Do not land Option A as "the fix for the truncated-frame failures."** Those attribute
   to the oversized-response drop (fixed 2026-08-25) and to the client/server timeout
   asymmetry (§8.2) — a re-run of the 08-11 scenario on a current build is expected to
   show a different failure surface.
2. **Option A remains justified for what it actually addresses**: the completion race and
   the two no-wait Rust sites, which are the only mechanism consistent with the
   `Connection refused` tail. Bound every wait strictly under the measured **5 s** kill
   ceiling — the refuted plan's 30 s bound is now measured, not just argued, to be
   unreachable.
3. **Add to the same review**: setting `--privileged-helper-timeout-ms` in the daemon
   plist to match the helper (§8.2), and re-wording the
   `annotate_helper_response_read_error` causal claim.
4. **Before final sign-off**, run the deferred live matrix (§8.3) and observe one induced
   residue-marker firing (§8.4) — the instrumentation and a current-build binary are
   already on the guest.

### 8.6 Evidence appendix (raw, abridged only by elision marks)

No orchestrator run directory applies (no stages were launched), so per the brief the raw
evidence lives here.

**Kill ceiling** (`launchctl print`, guest, 2026-08-27):

```
$ sudo launchctl print system/com.rustynet.privileged-helper | grep -iE "timeout|exit"
		--timeout-ms
	exit timeout = 5
	last exit code = (never exited)
$ for s in com.rustynet.anchor com.openssh.sshd com.rustynet.exit; do sudo launchctl print system/$s | grep -i "exit timeout"; done
	exit timeout = 5
	exit timeout = 5
	exit timeout = 5
```

**Helper idle-timeout probe** (root unix-socket client, helper pid 311, `--timeout-ms 30000`):

```
run 1: connected t0=1787869322.855 helper_pid_before=311
       unexpected data b'R' after 60.007 s
       helper_pid_after=311 alive=yes
run 2: connected t0=1787869546.709 helper_pid_before=311
       +60.011 s recv 89 bytes; EOF after 60.012 s; total bytes=89
       frame: magic=b'RNHF' version=1 type=2 payload_len=79
       payload: b'\x00\x00\x00\x00\x01\x00Hread frame header failed: Resource temporarily unavailable (os error 35)'
       helper_pid_after=311 alive=yes
```

**Deployed timeout configuration** (guest plists, 2026-08-27): helper plist
`--timeout-ms 30000`; daemon plist contains **zero** occurrences of
`privileged-helper-timeout` (grep count 0) → daemon client default 2000 ms.

**Residue-check negative paths** (guest, fresh `4b0d18aa` binary):

```
$ rustynetd shutdown-residue-check --state /usr/local/var/rustynet/rustynetd.state    # as uid 501
rustynetd shutdown left dataplane residue [policy_reject (78)]: shutdown rollback failed (fail-closed): marker present but undecodable at /usr/local/var/rustynet/rustynetd.state.shutdown-residue.json (read failed: Permission denied (os error 13)); treated as residue
residue-check-exit=78
$ sudo rustynetd shutdown-residue-check --state /usr/local/var/rustynet/rustynetd.state
shutdown-residue-check: clean (no marker at /usr/local/var/rustynet/rustynetd.state.shutdown-residue.json)
exit=0
```

**Unified-log teardown windows retained on the guest** (bounded `log show`, launchd
process, `com.rustynet.daemon|privileged-helper`, 2026-08-26):

```
10:56:37.886 removing service: com.rustynet.privileged-helper   (preceded by "service inactive")
10:56:37.888 removing service: com.rustynet.daemon              (preceded by "service inactive")
10:59:44.845 removing service: com.rustynet.daemon              ("service inactive")
10:59:44.883 removing service: com.rustynet.privileged-helper   ("service inactive")
11:22:38.984 removing service: com.rustynet.privileged-helper   ("service inactive")
11:22:38.986 removing service: com.rustynet.daemon              ("service inactive")
11:25:49.160 removing service: com.rustynet.daemon              ("service inactive")
11:25:49.210 removing service: com.rustynet.privileged-helper   ("service inactive")
```

No `signaled service` / `Terminated: 15` / `scheduling cleanup` lines exist in the
retained window — all recorded bootouts hit already-exited jobs.

**Guest state after this task**: `macos-utm-1` powered on by this task and powered off at
the end (it was off beforehand); helper left running untouched at `--timeout-ms 30000`
until the power-off; daemon left NOT loaded (as found); `/usr/local/bin/rustynetd`
replaced with the `4b0d18aa` build (the 2026-08-26 binary was overwritten — the next
orchestrator deploy re-installs its own build regardless); probe scripts left in the
guest's `/tmp`. The per-guest QH-18 flock for `macos-utm-1` was probed and free throughout.
