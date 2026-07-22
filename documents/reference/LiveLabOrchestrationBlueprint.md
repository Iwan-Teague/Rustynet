# The Live-Lab Playbook

### A blueprint for building an automated, evidence-grade, multi-environment test orchestrator for any project

---

## 0. Purpose and how to use this document

This document generalizes the lessons of building a real, working live-lab orchestration
system into a project-agnostic blueprint. It is not about any particular product's domain
logic — it is about the *machinery* you build around a project so that "does this actually
work, for real, on real machines" has a fast, automated, trustworthy answer.

It is organized so you can:

- Read §1–§2 once, as orientation, before you design anything.
- Use §3–§6 as the architecture reference while you build the orchestrator itself.
- Use §7 as a checklist while you write every single validation/test function — this is
  the section that will save you the most pain, because almost every hard-won lesson here
  came from a test function that *looked* correct and returned *plausible* data that was
  quietly wrong.
- Use §8 every day, as the actual operating discipline for how you commit, run, patch, and
  re-run without corrupting evidence or wasting VM/machine time.
- Use §9–§12 as you mature the system (dashboard, triage automation, AI-assisted operation,
  security-sensitive testing).
- Use §13 as a literal step-by-step starter checklist when you begin this on a new project.
- Use the appendices as copy-paste-adjacent schema templates.

A note on scale: everything below applies whether your "live lab" is three virtual machines
on a laptop, a fleet of cloud instances, a rack of physical devices, or a set of real mobile
handsets on a test bench. The pipeline shape and the pitfalls are the same; only the
provisioning mechanics change.

---

## 1. What a "live lab" is, and why CI alone isn't this

Unit tests run in-process. Integration tests run against fakes, mocks, or a same-host
service. CI runs both of those, usually in an ephemeral, homogeneous container, once per
push. All three are necessary and none of them can answer the question a live lab exists to
answer:

> **Does the real, built artifact behave correctly when deployed onto real, heterogeneous,
> independently-running machines, talking to each other over a real network, under real
> timing?**

A live lab is warranted whenever any of these are true for your project:

- The software runs on more than one OS/platform and behavior genuinely differs
  per-platform (permissions models, network stacks, service managers, filesystem
  semantics).
- The software's correctness depends on *distributed* state — two or more independent
  processes/machines that must agree, converge, or hand off correctly.
- The software has a privileged or security-sensitive surface where "it compiles and the
  mock test passes" is not sufficient evidence (mocked tests passing while a real
  interaction silently fails is a specific, recurring failure mode — see §7).
- Timing, ordering, or resource contention across real machines is part of what you need to
  prove (a race that never shows up against an in-memory fake will show up over a real
  network).
- You need historical, auditable evidence that a specific commit really worked on a real
  target, not just "the tests were green" — e.g. for a security or compliance posture, or
  because platform-parity claims will otherwise be unverifiable assertions.

If none of those apply, you probably don't need this system — a good CI matrix will do. If
even one applies strongly, build this; it pays for itself the first time a "should be fine"
change breaks something that only a real device would have shown you.

---

## 2. First principles

These are the rules that must survive contact with a deadline. Write them down somewhere
your future self (or teammate, or AI agent) will actually read before touching the system.

1. **Live result IS the result.** A stage's pass/fail must come from the real action against
   the real target, not from a dry-run/plan-check standing in for it. The single most
   expensive bug class in this whole domain is a validator whose "success" path is actually
   a static check that never touched the live system, while the real interaction silently
   failed. See §7.1 for the canonical anatomy of this bug and §2a below.
2. **No silent fallback for a security- or correctness-sensitive check.** If a control is
   supposed to fail closed, verify that it *does*, on the real target, with a negative test —
   not just that the happy path passes.
3. **Evidence over assertions.** Every run must leave behind an artifact trail (logs, machine
   -readable status, timestamps, the exact commit under test) sufficient for someone else —
   or you, in six months — to reconstruct exactly what happened and why a stage passed or
   failed, without re-running it.
4. **One hardened execution path.** Don't maintain two ways to run the orchestrator (a "real"
   path and a "legacy/simplified" path) that can silently diverge in what they actually
   verify. If you must keep an old path alive during a migration, mark it explicitly
   secondary and never let its results overwrite the primary evidence ledger (see §6.6).
5. **Fail closed on missing or stale information.** If the orchestrator can't determine
   whether a target is ready, whether a stage's log exists, whether a role is elected — the
   default answer is "don't proceed / don't count this as pass," never "assume yes."
6. **Small, verifiable increments.** Patch one thing, verify it against reality (not just
   against your assumption of reality), then move to the next thing. §8 is built entirely
   around this.
7. **The system that watches the lab must never lie about the lab.** A dashboard, monitor, or
   status reporter is worse than useless if it shows plausible-looking numbers that don't
   correspond to ground truth. It should read the same ledger the orchestrator writes,
   never maintain a second, independently-computed notion of state. See §9.

### 2a. The founding war story (learn this before you write your first stage)

A validation stage for one platform's role had a "live" path (SSH into the real host, run
the real command, check the real output) and a dry-run/plan-check fallback for when the live
path wasn't reachable. The live path had a wrong credential and silently failed to connect;
the fallback caught the failure, treated it as "the plan looks correct," and reported
**Pass**. The stage passed clean multiple times before anyone noticed the feature it claimed
to validate had never actually run on that platform.

The fix that followed became a standing rule (see §7.1): a stage's outcome is Pass or Fail
strictly from the outcome of the live action. A dry-run/plan artifact may be captured
*alongside* the result for debugging, but it may never *become* the result. This single rule
prevents the most expensive class of bug in this entire domain, and it is worth re-deriving
from scratch here because every project eventually invents its own version of "just check
the plan is valid" as a shortcut, and it is always wrong for the same reason.

---

## 3. The logical pipeline

Regardless of domain, a live-lab run decomposes into the same ordered phases. Not every
phase needs code in a simple system, but naming them explicitly stops you from silently
skipping one.

```
 PREFLIGHT → PREPARE → DEPLOY (bootstrap) → ESTABLISH → VALIDATE → [CHAOS/STRESS] → CLEANUP → REPORT → ACT
```

### Phase 1 — Preflight / discovery
Before touching anything: are the target machines powered on and reachable? Are their
clocks sane (a machine with a badly-skewed clock will produce nonsensical timestamps and can
break anything relying on freshness/expiry — verify and correct clock skew *before* the run,
not after a mysterious failure)? Is there a stale process/lockfile from a previous crashed
run that needs clearing first? Do you have credentials/keys primed for every target you're
about to use? This phase should be cheap, fast, and should fail the whole run immediately
and clearly if a target isn't usable — don't let a target-selection problem masquerade as a
test failure three phases later.

### Phase 2 — Prepare (get the artifact ready to ship)
Build or otherwise produce the exact artifact under test. Decide deliberately how the
*source* for a run reaches each target:
- **Archive-and-ship** (build once, or archive the working tree, and push the same bytes to
  every target) — best when you need every target running the literal same build, including
  uncommitted local edits during fast iteration (§8).
- **Pull-from-source-control at a pinned ref** — best for the "authoritative, evidence-grade"
  run where you want the ledger to record a real, reproducible commit.
- **Pull-from-a-registry/artifact-store** — best when the build is expensive and shared
  across many runs/targets.

Whichever you pick, the orchestrator must **know exactly what it shipped** and be able to
answer "is what's actually running on the target the thing I think I just deployed?" — see
the "confirm the fix actually landed" pitfall in §7.9.

### Phase 3 — Deploy / bootstrap
Install and configure the software under test on each target. Two structural decisions here
matter a lot for how fast your iteration loop can be:

- **Series vs. parallel deployment.** If bootstrap is a heavy, resource-constrained
  operation (e.g. a from-source compile on a memory-limited VM), doing it one target at a
  time avoids resource contention (see the OOM pitfall in §7.14) but makes the phase's
  wall-clock time scale with the number of targets. If bootstrap is cheap (copying a
  pre-built binary), parallelize freely. Whichever you choose, your time-estimate/ETA logic
  (§9.2) needs to know which model applies, or its estimates will be nonsense.
- **Full rebuild vs. incremental.** Once you have more than a couple of targets, build in a
  way to redeploy *only the targets whose configuration actually changed*, keeping the
  others' state warm. This is the single biggest lever for iteration speed once you're past
  initial buildout (§8.1).

### Phase 4 — Establish (cross-target state / trust / wiring)
Whatever needs to be true across targets before you can validate real behavior: nodes need
to discover each other, agree on a shared config, exchange credentials/trust material,
converge on a shared view of the world. Treat this as its own phase with its own pass/fail —
if establishment fails, every downstream validation stage is meaningless and should be
skipped, not attempted (see "chain on the live result," §7.1).

### Phase 5 — Validate (the actual tests)
This is where you assert the real, observable behavior of the system: the actual feature
under test, running for real, checked against a real outcome. §7 is entirely about how to
write these stages so their result is trustworthy.

Distinguish, in your stage catalog, between:
- **Golden-path validations** — the feature works under normal conditions.
- **Security/negative validations** — the system fails closed, rejects malformed input,
  enforces its boundary, when you deliberately push on it. These are not optional
  nice-to-haves; a security-relevant system is not "tested" until its fail-closed paths have
  been exercised for real (§12).
- **Cross-target / integration validations** — behavior that only two-or-more coordinating
  targets can exhibit (this is usually where the hardest, highest-value bugs live).

### Phase 6 — Chaos / stress (optional, but valuable once the golden path is solid)
Deliberately perturb the running system — kill a process, flap a network link, exhaust a
resource, restart a target mid-operation — and verify recovery. This phase is expensive to
build well and easy to get subtly wrong (see the network-flap / recovery-detection pitfalls
in §7). Don't attempt it until Phase 5 is reliably green; a flaky chaos stage on top of an
unreliable golden path just produces noise.

### Phase 7 — Cleanup
Tear down anything the run created (temporary state, injected impairments, elevated sessions)
so the target is fit for the next run. This must be **unconditional** — see §5.5 for how to
make that guarantee hold even when an earlier phase crashed or was killed.

### Phase 8 — Report
Write the run's outcome to durable, machine-readable storage (§6) before you do anything
else with the result. A run whose evidence only exists in a terminal scrollback is a run
that didn't happen, as far as anyone auditing later is concerned.

### Phase 9 — Act on the report
Feed failures into your triage/fix loop (§10) and, if you're running this system inside a
dashboard/monitor, update the live view. This is the phase most likely to be skipped in a
minimal build — don't skip it; a report nobody looks at is ceremony, not testing.

---

## 4. Topology and role modeling

Most live labs test a **cross-product**: some number of *roles* (the different jobs a
target can perform in the system under test) against some number of *platforms/environments*
(the different OSes, hardware, or deployment shapes you support). Model this explicitly:

- **Roles** are logical jobs, not machines — a role should be assignable to any eligible
  target, and your orchestrator should let you *elect* which target plays which role for a
  given run, rather than hard-coding "target A is always role X."
- **Parity tracking**: maintain a grid of role × platform, and track, per cell, whether it
  has ever been *proven* — meaning a real, live, passing validation exists for that exact
  combination, with a pointer to the evidence. This turns "is macOS support finished?" from
  an opinion into a lookup. Do not let a cell read as proven from a stage that ran but wasn't
  the FAIL-LOUD live form (§2a) — a dry-run pass must never paint a parity cell green.
- **Node assignment** should be recorded in the run's own manifest at the *start* of the run
  (see §6.2) — not reconstructed after the fact from log-scraping — so that anything
  monitoring the run mid-flight (a dashboard, an ETA calculator) has ground truth to read
  from the moment the run begins, not only once it ends.

---

## 5. The orchestration engine

### 5.1 Model it as a state machine, not a script

However you implement it, the engine's core concept is: an ordered (or partially-ordered) set
of **stages**, each with a **status** (not_run / running / pass / fail / skipped / timed_out),
transitions driven by real outcomes, and a **skip cascade** — if stage N fails or is skipped,
everything that depends on it is marked skipped, not silently left "not_run" forever or,
worse, attempted anyway against broken state. Make the dependency itself explicit and
queryable: declare each stage's direct prerequisite stage IDs in the catalog, and compute a
stage's live eligibility as the AND of all prerequisites' terminal-pass status, transitively.
Phase boundaries (§3) are usually the coarse-grained version of this (nothing in a later phase
runs if the previous phase didn't pass); explicit per-stage prerequisites are the fine-grained
version, for when two stages in the same phase still depend on each other.

### 5.2 Stage catalog vs. stage plan

Keep two distinct concepts and don't conflate them:

- The **catalog** is every stage that could conceivably run, across every role/platform/mode
  your system supports.
- The **plan** for *this specific run* is the enabled subset, computed from the run's
  topology/selectors (which roles are elected, which platforms are in play, which optional
  suites were requested).

A stage that's in the catalog but not in this run's plan should render as clearly
**not-applicable**, not blank and not "not yet run" — these three states get confused
constantly if you don't name them distinctly (see the recurring "eligible-total vs. run
-relevant-total" pitfall in §7.17).

### 5.3 Two different numbers per stage: the timeout budget and the realistic estimate

This is one of the most valuable, least obvious lessons in this whole document, learned the
hard way:

- The **cold-start timeout budget** is the worst-case ceiling — how long you'll let a stage
  run before declaring it stuck. This number should be generous.
- The **realistic expected duration** is what a *healthy* run actually takes — usually far
  smaller, based on real historical measurement (a rolling percentile, e.g. P90, of past
  passing/terminal runs of that exact stage, times a small safety margin).

**Never use the timeout budget as the basis for an ETA or health estimate.** Summing 30
stages' worst-case timeout ceilings produces an estimate that is off by an order of
magnitude (a live phase that actually finishes in three minutes can "estimate" at over two
hours this way) — and once you've seen the resulting absurd estimate, the fix is obvious in
hindsight but easy to never think of if you haven't hit it: maintain the two numbers
completely separately, feed the timeout into "should I declare this stuck," and feed the
realistic estimate (with a sane hard-coded default for any stage that has no history yet)
into anything a human will actually read as "time remaining." See §9.2 for the dashboard
-facing version of this same lesson.

### 5.4 Series-phase-aware progress

If any phase deploys/bootstraps targets in series (§3, Phase 3), a naive wall-clock
countdown for that phase is wrong in an important way: it doesn't account for targets that
have *already* finished within the phase. Track, per phase, `(targets_finished,
targets_total)` from real, verifiable per-target completion markers (not from a
finalize-time-only file that doesn't exist until the whole run ends — that's a real bug you
will hit if the obvious data source is only written at the very end) and drop a whole
per-target time-slice off your estimate as each target completes. This makes the estimate
self-correct in real time instead of just ticking down a fixed number regardless of what's
actually happening.

### 5.5 Guaranteed teardown

Register your cleanup/teardown logic so it runs on graceful completion, on a stage failure,
*and* on external interruption (a captured termination signal) — not just at the natural end
of a successful script. An orchestrator that leaves residue behind after being killed will
poison the next run's evidence in ways that are maddening to diagnose (a "failure" that's
actually leftover state from the previous, forcibly-stopped run).

---

## 6. The data model — how to store everything

Storage discipline is not an afterthought here; it is the entire point. If the live run's
result isn't durably, unambiguously recorded, the run might as well not have happened. Four
distinct artifacts, each with a distinct job — do not merge them into one file, and do not
let two different tools each maintain their own "count" against the same underlying facts
(a recurring, confusing bug class: a header total and a detail-panel total computed from two
subtly different definitions of "what counts" — always have exactly one definition, shared).

### 6.1 The per-run report directory

Every run gets its own directory. Inside it:

- **A stage-status ledger** — one row per stage, appended/updated (upsert) as the run
  progresses, machine-parseable (tab- or comma-separated, never free-text-only), with at
  minimum: stage name, status, exit/return code, a pointer to that stage's log file, a short
  human summary, and start/end timestamps. This file is the **single source of truth for
  "what's happening right now"** — anything watching the run live (a dashboard) reads *this*
  file, not the stdout stream, not a guess.
- **Per-stage log files**, one per stage, named predictably (so a dashboard/tailer can find
  "the log for the currently-running stage" without guessing). A stage that runs across
  multiple targets in parallel needs a way to disambiguate whose output is whose (see the
  log-tailing pitfall, §7.7).
- **A run manifest**, written at or near the *start* of the run (not reconstructed at the
  end): the plan (which stages are enabled and why), the node/target assignments, the
  per-stage timeout budgets, and the exact invocation (command/flags) that started this run.
  This is what lets anything monitoring the run mid-flight know the ground truth (§5.2, §5.4,
  §9).
- **A final result file**, written once, at the very end, atomically (write-then-rename, or
  fsync-then-close) so a reader can never observe a half-written result: overall pass/fail,
  per-stage outcomes, and the exact set of artifacts produced.
- **A "run complete" marker**, distinct from "run passed" — you need to be able to tell
  "finished (successfully)," "finished (with failures)," and "never finished (crashed/killed)"
  apart, and a monitoring layer needs the *complete* signal specifically to know when to stop
  polling this directory as "live" (see the orphan-detection pitfall, §7.16).

### 6.2 The run manifest schema

Written at or near the run's start (see Appendix A.2 for the full template): the plan (which
stages are enabled and why), the node/target assignments, the per-stage timeout budgets, the
exact invocation that started this run, and — critically for §8.2 — the exact source revision
and clean/dirty state the run is attesting to.

Two boolean flags per stage are easy to conflate but answer different questions:
`counts_as_check` is whether a stage counts toward coverage (plumbing like setup/cleanup
usually shouldn't); `synthetic` is whether the stage is a placeholder/diagnostic-only entry
rather than a real assertion — a stage can be non-synthetic but still not count (cleanup), or
synthetic and still counted if you choose to. Keeping both as a clean, shared boolean per
stage lets every downstream consumer (a summary count, a coverage percentage, a dashboard)
agree on "how many real tests ran" without each one inventing its own filter and drifting
apart (§7.17).

A stage's `enabled: false` here means **not-applicable to this run's topology** — it never
gets a ledger row at all. That's a different thing from a ledger `status=skipped` (§6.3),
which is a **runtime cascade-skip** (§5.1) of a stage that WAS enabled but got skipped because
a prerequisite failed. Conflating the two recreates exactly the not-applicable-vs-skipped
trap §5.2 warns about — don't let your own schema make that mistake easy.

### 6.3 The stage-status ledger schema

A simple, append-friendly row per stage-transition (see Appendix A.1 for the exact columns).
`status` should be one of a small closed set — running / pass / fail / skipped / not_run /
timed_out / reused (if you support resuming) — and every consumer of this file should agree
on which of those count as "terminal" for progress-counting purposes (only one row per stage
should ever be "running" at a time; anything else is a bug in the writer).

### 6.4 The historical run-matrix ledger (across ALL runs, forever)

Separate from any single run's own directory: a long-lived, append-only ledger recording
one row per historical run, wide enough to answer "what has this exact role×platform
combination ever proven, and when, at what commit" (see Appendix A.4 for minimum columns).

This is your parity matrix's data source (§4) and your regression-detection data source
(§10.4) — "did this used to pass, and when did it stop." Guard it against two failure modes:

- **Concurrent-run collisions.** If two runs can finish near-simultaneously, a naive
  read-modify-append to a shared file can interleave and corrupt a row. Use a real
  file lock (advisory lock) around the append, or route all writes through a single
  writer process.
- **Ledger identity confusion.** If you ever migrate to a new orchestration engine while an
  old one is still in occasional use, the two must write to *visibly distinct* ledgers (or a
  clearly tagged `engine` column) — never let a reader accidentally treat one engine's
  historical passes as evidence for the other engine's current state. This is a real,
  easy-to-make mistake: two engines can diverge so far that one has never achieved a result
  the other recorded dozens of times, and conflating them silently overstates your actual
  coverage.

### 6.5 The failure/triage ledger

A separate, append-only, structured log (JSON-lines works well) of every diagnosed failure and
what was tried (see Appendix A.5 for the record shape). The payoff for keeping this is
realized in your triage workflow (§10.1) — check it by stage name before diagnosing from
scratch, every time.

### 6.6 Never conflate two ledgers written by two different mechanisms

If, during the system's life, you replace or add a second orchestrator implementation, its
evidence and the original's must not land in the same "current truth" ledger unless the two
are genuinely computing the same thing. Keep the legacy one frozen/read-only and clearly
labeled as historical, and make the *current* engine's ledger the only one anything live
reads from. Document this distinction somewhere loud (a top-line comment in the ledger file
itself, and in your project's main operating instructions) — this is exactly the kind of
thing that silently causes someone (or an agent) to cite the wrong evidence months later.

### 6.7 Credentials never live in the tracked ledger/inventory

If your lab needs credentials to reach targets (SSH passwords, API keys, device-unlock
codes), and your inventory/config file describing those targets is version-controlled,
**do not put secrets in it** — even in a private repository; repositories go public, get
forked, or get their history mined more often than teams expect. Store secrets in a
separate, untracked, permission-locked sidecar file, keyed by the same alias your tracked
inventory uses, and merge them in at load time. Enforce this with an automated check that
fails the build/gate if a secret-shaped value drifts back into the tracked file. If you ever
find you've already committed a secret, treat the credential as burned and rotate it — don't
assume history rewriting alone fixes it once something has been pushed.

---

## 7. Writing validators that return accurate live data — the pitfalls catalog

This is the section to re-read every time you write a new validation stage. Every single one
of these was learned by actually shipping the bug, not by reading about it.

### 7.1 The dry-run-as-pass trap (see §2a)
Never let a stage's pass/fail come from anything other than the real, live action's real
outcome. A plan-check/dry-run may be captured as a diagnostic artifact but must never
substitute for the live result. Chain: a downstream stage should only attempt its own live
action if the upstream stage's *live* result was a real pass — never "skip straight to pass"
because an earlier stage looked plausible.

### 7.2 The subprocess-rebuild-clobbering trap
If a test/validator shells out to your own build tool (`your-build-tool run ...`) as part of
its execution, that subprocess can **rebuild the very binary the orchestrator is currently
running**, silently replacing it mid-flight — possibly with a different configuration
(missing a compile-time feature flag the orchestrator needs, see §7.3) than the one that was
deliberately deployed. If a validator needs to invoke logic from your own codebase, call it
**in-process** (a library/module function call) rather than shelling out to a rebuild. If you
must shell out to an external process, shell out to something that does *not* rebuild your
own orchestrator (a genuinely separate tool), and be explicit about it.

### 7.3 The optional-feature/compile-variant trap
If any capability your orchestrator needs is gated behind a build-time flag/feature (e.g.
lab-only tooling compiled out of your normal release build), any incidental rebuild during
the run — including one triggered by the pitfall above — can silently strip that capability
back out. **Don't assume a rebuild preserved your required build configuration; verify it.**
A cheap, reliable check: after any rebuild you didn't explicitly control, probe the resulting
binary for the expected capability (e.g. grep its own `--help`/subcommand-listing output for
an expected command name/count) rather than trusting that "it built" means "it built the way
I need." A build that silently drops a whole subsystem still exits 0 and still runs — it
just does far less than you think, and the failure mode looks exactly like "everything is
suddenly broken" with no obvious cause.

### 7.4 The PATH-dependent remote command trap
When a validator invokes a command on a remote target over a non-interactive/non-login
shell (most SSH-driven automation), that shell's `PATH` is frequently a stripped-down
subset of what an interactive login shell would have. A bare command name that resolves fine
when you test it by hand can fail to resolve at all when the orchestrator runs it, producing
an error that looks like "the product is broken" when it's actually "the harness couldn't
find the binary." **Invoke remote commands by absolute path** wherever the target's install
location is known and stable, rather than relying on PATH resolution.

### 7.5 The role/state-propagation-lag trap
A configuration or role change applied to a remote target (e.g. "this node is now the
coordinator") may take a real, non-zero amount of time to propagate into that target's own
reported status. A validator that reads status **once, immediately after applying the
change**, and treats a mismatch as a hard failure will produce **flaky false failures** that
have nothing to do with correctness and everything to do with timing. Build a **bounded
retry** (a small, fixed number of attempts with a fixed delay between them) into any check
that reads state shortly after a change that state depends on. Pick the attempt count and
delay empirically — long enough to absorb real propagation lag, short enough that a genuine
failure still fails in reasonable time — and make the number of attempts and the delay
explicit constants near the check, not a magic number buried in a loop.

### 7.6 The sandbox-blind probe trap
A network/reachability probe run from inside an automated/sandboxed environment (an agent
runtime, a locked-down CI runner, a restricted execution context) can behave *differently*
from the same probe run in a normal interactive shell — sometimes reporting a target as
unreachable when it is in fact fine, purely because of how that sandbox mediates raw socket
access or local-network permissions. If you ever see a reachability check fail in a way that
contradicts other evidence (the target answers fine to the exact same probe run
"by hand"), suspect the execution environment before you suspect the target or the code. The
practical fix is usually one of: (a) prefer a real, full protocol handshake (e.g. actually
completing an SSH connection) over a raw low-level socket probe as your readiness signal —
the higher-level protocol tooling tends to be exempted from sandbox restrictions that a raw
probe is not — or (b) run that specific class of probe from a genuinely unsandboxed process.
Don't chase this per-target or "fix" it by editing your target inventory; if it's a sandbox
artifact it will affect every target identically and the fix is environmental, not
per-target.

### 7.7 The "which log am I even looking at" trap (parallel/multi-target stages)
If a single logical stage fans out across multiple targets in parallel, a naive "tail the
stage's log file" assumption breaks — there is no one file, or the one file interleaves
unrelated targets' output. Either give each target's slice of a parallel stage its own
distinctly-named log (and have your log-tailer pick the most-recently-active one, e.g. by
modification time, with a small header naming which target it's from) or write a structured
per-target result row instead of raw log tailing.

### 7.8 The stale-content-in-a-shared-buffer trap
If your monitoring/reporting layer reuses one in-memory buffer for two different purposes
(e.g. "the tail of the current stage's log" *and* "the last user-facing status/action
message"), you will eventually observe a stage whose log file doesn't exist yet (because the
stage hasn't produced output, or produces none by design) silently displaying **the previous,
unrelated message** instead of anything about the current stage — because the code only
*overwrites* that buffer when there's new content, and never explicitly clears it when there
isn't. The fix is to make the "nothing to show yet" case an explicit, first-class state (a
placeholder keyed to the specific thing you're waiting on, e.g. "waiting for `<stage
name>` output…") rather than an implicit fallthrough that happens to retain whatever was
there before.

### 7.9 The "did the fix actually land" trap
Before trusting a re-run as evidence that a fix worked, confirm the fix is **actually present
on the target you just tested** — don't assume a deploy step succeeded just because it didn't
error. A cheap, reliable check: verify some observable signature of the new code/config is
present on the target (a version string, a build timestamp, a behavioral marker) before
treating the re-run's result as meaningful. "The binary wasn't actually rebuilt" is a
real, recurring failure mode, not a hypothetical one.

### 7.10 The exact-match-vs-any-match trap (security-relevant checks especially)
When you add a new narrow allowance to a security-sensitive gate (an allowlist entry, a
permitted argument value, a permitted range), the test that proves it's correctly scoped
must do **two things**, not one: prove the intended narrow value is accepted, **and** prove a
*different, same-shaped* value is rejected. A test that only proves "the value I added is
accepted" gives you zero evidence about scope — it would pass identically whether you
correctly restricted to an exact literal or accidentally opened up an entire type/range. Any
time you're tempted to write "accepts X," immediately also write "rejects Y, which is the
same kind of thing as X but isn't X."

### 7.11 The overdue-vs-failed-vs-skipped conflation trap
Track (and render, if you have a dashboard) three genuinely distinct states as three distinct
states: **overdue** (still running, but past its expected/healthy duration — a health signal,
not a failure), **failed** (terminated with a real error), and **skipped** (deliberately not
run for this topology/config, not a failure at all). Collapsing these into a binary
pass/fail (or worse, into a generic "not green") destroys the single most useful signal for
"is this hung, or did it actually break, or was it never supposed to run" — three questions
with three very different next actions. A fourth case belongs in `failed`, not `skipped`: a
target that *should* have been checkable but the check itself errored, timed out, or came back
ambiguous. "Couldn't verify" is not the same as "not applicable" — silently treating an
unverifiable result as a legitimate skip is how an unproven cell paints green on a parity
matrix (§4).

### 7.12 The two-numbers-for-time trap
Every stage's timeout ceiling and its realistic-duration estimate are different numbers,
computed and used differently — see §5.3. Never derive one from the other.

### 7.13 The repeated-forced-restart destabilization trap
If a validator's failure-recovery path is "if the target seems unresponsive, forcibly
restart it and try again," be careful about doing this in a tight, automatic retry loop
without a cooldown or root-cause check. Repeated forced restarts of a resource-constrained
target (especially one already under memory or I/O pressure from the very build/bootstrap
step you're retrying) can *compound* instability rather than resolve it — turning a transient
hiccup into a target that reliably fails for several restart cycles before finally settling.
Prefer: detect the specific unhealthy signal, wait a bounded, deliberate amount for natural
recovery, and only escalate to a forced restart with a real, human-visible cooldown between
attempts. If a target needed a restart to recover, treat that as worth investigating (why did
it need one?), not just worth automating away.

### 7.14 The build-under-memory-pressure trap
If your deploy/bootstrap step compiles from source (rather than shipping a pre-built
artifact) on resource-constrained targets, an aggressive optimization setting (e.g.
whole-program/LTO-style optimization, single-codegen-unit builds) can push memory usage right
to — or past — the target's ceiling, causing an out-of-memory crash that looks exactly like
"the target went down for no reason." If you see a target crash specifically during a build
step and recover fine afterward, suspect build-time memory pressure before you suspect
anything else, and either raise the target's memory allocation or relax the optimization
setting for lab targets specifically.

### 7.15 The clock-skew trap
A target whose system clock is meaningfully wrong (drifted, paused-and-resumed by its
hypervisor, never synced) will produce nonsensical timestamps that can break anything
relying on freshness, expiry, or ordering — and will fail your **preflight** phase in
confusing ways if you don't check for it explicitly. Re-sync clocks as a matter of routine
immediately before a run on any target with a history of drifting, and treat a target whose
clock keeps drifting shortly after a resync as a target-level environmental issue to flag,
not a product bug to chase.

### 7.16 The phantom-still-running trap
Anything monitoring "is a run currently active" needs **both** a liveness signal (the
process is actually alive) **and** a staleness window (there's been genuinely recent
activity in that run's evidence directory) — neither alone is reliable. A process-id check
alone can be fooled by ID reuse or by a stale record that never got updated after a crash. A
"there's an incomplete run directory" check alone can't tell a truly-abandoned, killed run
from one that's simply between stages. Combine both: treat a run as live only if there's
been activity within a defined recent window *and* (where checkable) the owning process is
actually alive; otherwise treat it as an orphan and don't let it masquerade as "currently
running" to a human or a dashboard.

### 7.17 The coverage-fraction trap: two ways to miscount
Any time you compute "how many stages/checks ran out of how many possible," two different
mistakes produce the same symptom — a fraction that's individually defensible but disagrees
with a fraction shown somewhere else in your system:
- **Filter drift.** Every consumer of that fraction (a summary header, a detail panel, a
  historical trend view) must use **the exact same definition** of both numerator and
  denominator. It is very easy for two pieces of code, written at different times by
  different people, to each invent a slightly different filter for "what counts" — one
  includes synthetic/plumbing entries, the other doesn't. Define "what counts" exactly once,
  expose it as a single shared function/flag (the `counts_as_check` idea in §6.2), and have
  every consumer call that, not reimplement it.
- **Scope drift.** Be explicit about which of three different populations a "coverage" number
  is counting: the full catalog of everything the system could ever check, the plan for one
  specific run (§5.2), or a rolling historical aggregate across many runs. Showing a
  catalog-wide denominator next to a single-run-plan numerator produces a fraction that's
  individually correct but contextually misleading.

### 7.18 The A/B-bisect-before-blaming-the-environment trap
When a stage that used to pass starts failing, there is a strong temptation to explain it
away as environmental flakiness ("the network's just being weird," "the VM's acting up
again") — especially if there's a *plausible*-sounding environmental story. Before accepting
that story, do a real, controlled A/B comparison: check out the last-known-good version of
the code (a separate worktree/checkout is ideal — it lets you build and run the old version
without disturbing your current working tree) and run the identical test, against the
identical target, with everything else held constant. If the old code passes and the new
code fails under otherwise-identical conditions, you have proven a real regression, not an
environmental theory — and you've usually also narrowed down which specific change caused it
far faster than reading logs would have. Don't skip this step just because the environmental
story sounds credible; plausible-sounding wrong explanations are the norm, not the exception,
in distributed-systems debugging.

### 7.19 The "which of my two ledgers is this evidence in" trap
If you're running two orchestration mechanisms side-by-side during a migration (§6.6), be
disciplined about checking failures/passes against the **correct** ledger for the mechanism
you actually used. Citing the wrong ledger as evidence for the current engine's state is an
easy, embarrassing mistake, and it compounds — once someone has cited it, others tend to
trust the citation rather than re-check it.

---

## 8. The operating rhythm — commit, patch, run, re-run etiquette

This section is the day-to-day discipline that makes the difference between "we have a live
lab" and "we have a live lab we can actually iterate against quickly, safely, forever." It's
written assuming a git-like version control system (commits, branches, a working tree, a
notion of "clean" vs. "dirty") — substitute your own VCS's equivalents throughout if it
differs.

### 8.1 Two speeds of run — know which one you're doing

Maintain, deliberately, **two distinct kinds of run**, and be explicit (to yourself, your
team, and any tooling) about which one you're doing at any moment:

- **Iteration runs** — fast, frequent, used while actively chasing a specific failure. These
  may ship *uncommitted* working-tree edits (archive-and-ship, §3 Phase 2) so you can test a
  change before committing to it. Because they run against uncommitted state, their result
  is **not** authoritative parity/coverage evidence — it's a fast feedback loop, nothing
  more.
- **Authoritative runs** — a clean run against a **committed, pushed** reference, used to
  produce the evidence that actually lands in your historical ledger (§6.4) as a real,
  reproducible proof point. These should refuse to run (fail closed) against a dirty working
  tree, or against a tree that has drifted from what it originally recorded — see §8.2.

Never let an iteration run's result get written into the same ledger slot as an authoritative
run's result. If your tooling can't tell the difference, add an explicit flag/mode so it can.

### 8.2 Provenance integrity — protect the authoritative run from concurrent edits

An authoritative run's entire value rests on the claim "this exact commit, unmodified, really
passed this exact test on a real target." That claim breaks the moment someone (including a
different session of you, or a teammate, or an automated agent) commits to the same branch
mid-run, or the working tree gets dirtied mid-run. Build an explicit **provenance check**
into the authoritative-run path: record the source revision and a clean/dirty flag in the run
manifest at start (`source_commit` / `source_clean`, Appendix A.2); at the point where the
run's evidence is about to be finalized/attested, re-derive both from the live tree and refuse
(fail closed, loudly) if either has changed since the run began.

Treat a provenance-check abort as a **feature working correctly**, not a bug to route around
— it caught a real integrity violation (this exact scenario, a concurrent commit landing
mid-authoritative-run, is exactly the failure mode it exists to prevent). Never weaken or
bypass this check to "get past" an abort; find out what actually raced and sequence around
it instead.

### 8.3 The concrete loop

```
edit code (small, single-purpose change)
  → run the fastest relevant local checks (formatting/lint/the touched module's own tests)
  → iteration run (fast; may use uncommitted state) against the live target
  → repeat until the specific thing you're chasing is green, for real, against a real target
  → commit (one logical change; message states what AND why)
  → run the FULL local gate suite (or confirm it's green from a recent background run)
  → authoritative run (clean, committed tree) — this produces the evidence-grade result
  → green? push. record the ledger row (§6.4). move to the next failure.
  → NOT green on the authoritative run even though iteration was green? treat this
    seriously — it usually means the iteration run was quietly exercising something
    subtly different than the authoritative one (stale cached state reused across
    iteration runs is the most common cause) — see §8.4.
```

Do not skip the "commit, then run clean" step as a shortcut. An iteration-only workflow that
never produces a clean authoritative pass leaves you with a pile of "probably fine" changes
and zero actual evidence.

### 8.4 Reused state is a hazard specifically at authoritative-run time

Fast iteration deliberately reuses warm state (an already-bootstrapped target, an
already-established cross-target trust/config) to go fast. This is valid **only** for
changes that don't touch whatever that reused state represents. If a change alters the
*shape* of that shared state (a wire format, a schema, a handshake/negotiation protocol, a
trust/credential format) — reusing old state doesn't just risk a false pass, it can actively
mask a real incompatibility. Any such change needs a full, fresh re-establishment (Phase 3–4
of §3) as part of its authoritative run, not a reused/warm one. Know, for every kind of
change you commonly make, whether it falls into this category, and default to "do the full
re-establishment" when unsure.

### 8.5 Never idle a target during a long run

A full run across many targets is typically the single longest wall-clock operation in your
day. Structure your work so you are never blocked *waiting* on it:

- Pre-stage the next fix's code changes in your working tree while a run is in flight —
  working-tree edits don't perturb a run that already deployed its frozen snapshot/build.
- Batch your heaviest, slowest local gates (full test suite, dependency/security audits) to
  run in the background during a lab run, so they're already done by the time you need them.
- Treat running a **second, concurrent run on genuinely idle targets** as an advanced, opt-in
  escape hatch — not a default lever. Enable it only when the timeline demands it, and only
  once you've confirmed all of: disjoint node sets, a separate report directory per run,
  direct (non-shared-job-queue) invocation, and host CPU/disk headroom for both runs at once.
  The ledger-append-lock issue (§6.4) is the most common trap even once those four hold —
  stagger completions or serialize the ledger append.

### 8.6 One logical change per commit; state the why

Commit messages should explain *why* a change was made, not just restate what changed (the
diff already shows what changed). This matters enormously for this system specifically
because a future triage session (human or automated) will often need to understand *why* a
past change was made in order to correctly classify a new failure as "this regressed
something we changed on purpose" versus "this is genuinely new."

### 8.7 Root-cause classification before you patch anything

When a stage fails, classify it into exactly one of three buckets before writing any code:

1. **A real defect** in the system under test → patch the system.
2. **An environment/lab flake** (a target-level issue unrelated to the code: see §7.13–§7.15
   for common causes) → recover the environment, retry, and do **not** touch the code.
3. **A correct fail-closed behavior that the test itself mis-expects** → fix the *test*, never
   weaken the control the test is checking. (Distinguishing bucket 3 from bucket 1 is exactly
   why the exact-match testing discipline in §7.10 matters — a test that only checks the
   happy path can't tell you whether a "failure" is the control correctly rejecting bad
   input.)

Misclassifying bucket 2 as bucket 1 wastes time chasing a phantom code bug. Misclassifying
bucket 3 as bucket 1 risks weakening a control that was working correctly. Take the time to
get this classification right before touching anything.

### 8.8 Definition of done, for a fix

A fix to a failing stage is done only when **all** of the following hold, not just the first
one you happen to reach:

- Root cause identified with real evidence (not guessed, not assumed from a plausible story —
  see §7.18).
- The smallest correct patch applied — no unrelated cleanup bundled in.
- Targeted local checks pass.
- The specific previously-failing stage now passes on a **real, live target** — not just in
  a unit test standing in for it.
- A subsequent clean, full, authoritative run is green and its ledger row is recorded.
- If the fix touched a security-sensitive control, a negative-path test exists proving the
  control still correctly rejects what it should (§7.10, §12).

"The unit tests pass" is necessary but never sufficient for this system — the whole point of
building it is that unit tests alone weren't enough evidence.

---

## 9. The observability layer (a live dashboard/monitor)

You don't strictly need a live dashboard to have a working system, but once a run takes more
than a few minutes and involves more than one or two targets, not having one is genuinely
painful. If you build one, hold it to a stricter standard than a normal internal tool: it is
actively harmful if it shows numbers that look plausible but don't match ground truth,
because the entire reason this system exists is to replace "looks fine" with "verifiably
is fine."

### 9.1 The one hard rule: read the same ledger, never compute a parallel truth

Apply First Principle 7 (§2) concretely: read the exact stage-status ledger and run manifest
the orchestrator itself writes (§6.1–§6.3) — never maintain an independent notion of "what
stage is running" or "how many have passed" computed by some other means (log-scraping
heuristics, guesswork, a stale cache) that can drift from the ledger's actual content. When in
doubt about what the dashboard should show, the answer is always "whatever the ledger
currently says," even if that's less satisfying than a smoother-looking guess.

### 9.2 ETA design, done right

Apply §5.3's two-numbers rule directly to whatever "time remaining" display you build:

- Compute remaining time per phase from the **realistic estimate**, not the timeout budget.
- For a phase that deploys targets in series, use the self-correcting, per-target-slice
  approach from §5.4 rather than a flat wall-clock countdown.
- Once you have this working, consider a further, genuinely useful refinement: display each
  phase's estimated **finish clock time** ("phase X will finish around 14:20") rather than a
  raw "minutes remaining" countdown. If your phases run in series, these compound naturally
  — the last phase's finish-time estimate becomes your overall run-completion estimate, and
  a single glance answers "when will this be done" far better than mentally summing three
  separate minutes-remaining countdowns.
- When a stage genuinely runs past its own realistic estimate, say so explicitly ("overdue by
  N minutes") rather than silently floor-clamping the displayed remaining time at some small
  positive number forever — a stage stuck for twenty minutes past its budget should not
  render identically to one that's one second over.

### 9.3 Log tailing, done right

- Tail the **currently active** stage's own log file; when that stage runs in parallel across
  multiple targets, disambiguate which target's output is shown (§7.7).
- When the active stage's log doesn't exist yet (nothing written so far), show an explicit
  "waiting for output" placeholder keyed to that specific stage — never silently retain
  whatever unrelated content happened to be displayed before (§7.8).

### 9.4 Orphan/staleness handling

Apply §7.16 directly: a dashboard's "is a run currently live" signal needs both a liveness
check and a staleness window, or a killed-but-not-cleaned-up run will show as perpetually
"running" long after it's actually dead.

### 9.5 Historical trend view, separate from the live single-run view

Keep a distinct panel/view for "how have recent runs gone" (pass/fail trend, parity matrix
status) sourced from the historical ledger (§6.4), clearly separated from the live
single-run view sourced from the current run's own ledger (§6.1–§6.3). Conflating "what's
happening right now" with "what's happened across history" in one view tends to produce a
display that's confusing about which numbers are live and which are historical.

---

## 10. Failure triage and the evidence-ledger discipline

### 10.1 Always check the triage ledger before diagnosing from scratch

Before spending time root-causing a fresh failure, look it up by stage name (and ideally
target platform/scope) in your failure/triage ledger (§6.5). If a **filled-in** prior attempt
exists for this exact stage:
- If the prior attempt's fix was believed to have landed, and the stage is failing again,
  this is a **regression** — treat it with urgency, and start your investigation from "what
  changed since that fix landed," not from zero.
- If the prior attempt shows an unfilled or clearly-abandoned diagnosis, at least you know
  someone already looked and didn't finish — don't silently repeat identical dead-end
  investigation.

A mature version of this: have the orchestrator itself auto-print any matching prior triage
attempts the moment a stage finalizes as failed, right into that run's own output/report —
this removes the "remember to go look it up" step entirely and puts the relevant history in
front of whoever (or whatever) is handling the failure at the exact moment they need it.

### 10.2 Regression vs. pre-existing frontier

When a run reaches further than before and then fails at a *new* stage it's never reached
before, distinguish clearly between "this is a brand-new, previously-unseen failure" (worth
fresh, careful diagnosis) and "this is the known, currently-being-worked frontier of what
this system can reach" (already tracked, don't re-diagnose from scratch — check what's
already known about it first). Getting this distinction right saves significant duplicated
effort, especially in a system worked on by more than one person or agent over time.

### 10.3 Record the fix alongside the ledger update, not separately

When you land a fix for a previously-triaged failure, update the triage ledger's record for
it (or add a new record linking back to it) in a way that's traceable to the actual commit
that fixed it. A historical record that says "this was fixed" with no pointer to what
actually fixed it is barely better than no record at all, six months later.

### 10.4 Use the historical ledger for real regression proof, not just record-keeping

The historical run-matrix (§6.4) isn't just a log — it's your regression-detection tool.
When something that used to reliably pass starts failing, that ledger tells you exactly when
it last passed and at what commit, which bounds your bisection search (§7.18) immediately,
without you needing to remember or guess.

---

## 11. Optional: AI-agent-assisted operation

If you use an AI coding agent to help operate or extend this system, the following division
of responsibility keeps it genuinely useful without letting it become a silent, unverified
authority over your evidence.

### 11.1 Two clearly separated tiers: read-only research vs. write-capable editing

- **Read-only research/triage tier**: an agent that can inspect the *actual* current
  repository and lab state — read real files, run real read-only commands, check real
  target reachability, query the real triage/run ledgers — to verify or refute a specific
  claim ("does this function actually still exist," "did this stage really fail because of
  X," "is this target actually reachable right now"). This tier should have **no** ability to
  write to the repository, no ability to run anything destructive, and no ability to make
  the final call on a security-sensitive question. Its entire value is that it's *grounded*
  — checking a claim against reality produces far fewer false conclusions than an agent
  reasoning only over text you've pasted to it.
- **Write-capable editing tier**: a genuinely separate mechanism, with a genuinely separate
  safety model, for when you want an agent to actually make code changes. The isolation is
  the entire safety model here, so don't compromise on it:
  - Every write-capable job operates in its **own isolated workspace** (a separate
    checkout/worktree on its own throwaway branch), never directly on your real working
    tree or main branch.
  - **No tool automatically merges that branch back.** Reviewing and merging (or discarding)
    the result is a deliberate human step, every time — this is the actual security
    checkpoint, and automating it away would defeat the entire point of the isolation.
  - Support (at minimum) a **supervised mode**, where every individual write pauses for
    explicit human approval before it's applied, for anything you want to watch closely, and
    a separate **unattended mode**, where the agent runs a whole task to completion and hands
    you a diff to review afterward, for work you trust it to attempt end-to-end.

### 11.2 Cheap-and-fast vs. slow-and-deep model tiers

Which model tier you use for routine vs. hard work is purely a cost/throughput optimization,
not a safety boundary — the safety boundary is the tier split in §11.1 (read-only vs.
write-capable), not which model answers a prompt. Route high-volume, low-difficulty work (log
digestion, first-pass triage) to a fast/cheap tier and reserve a deeper-reasoning tier for
genuinely hard root-cause work the fast tier keeps getting wrong.

### 11.3 Budget/quota ceilings and checkpointing

Give any autonomous agent job a hard resource ceiling (a token/usage budget, not a cost
estimate alone — provider pricing metadata is often incomplete, and only a resource-based cap
actually enforces a limit rather than just reporting one after the fact). Before killing a job
that hits its ceiling, make it **checkpoint** — commit to its own isolated branch, even a
"here's how far I got" state — so a long-running job's work isn't simply lost; the isolation
from §11.1 makes this free to do safely.

### 11.4 Adversarial verification before trusting anything security- or destruction-adjacent

For any diagnosis or proposed fix that touches something security-sensitive or hard to
reverse, don't trust a single agent's confident answer. Run a small panel of independent
checks (multiple attempts, or multiple distinct "try to find a reason this is wrong" prompts)
and treat disagreement among them as a signal to dig deeper yourself, not as noise to
average away. An agent's output in this domain should always be treated as **a proposal to
verify**, never as a decision already made — the human (or an equally grounded, independent
process) retains the actual call.

This extends to your evidence itself: never let an agent silently overwrite, "tidy up," or
prune your historical ledgers (§6.4, §6.5) — those are the record you're trusting an agent's
work against, and an agent that can quietly edit its own grading sheet defeats the entire
verification model above.

---

## 12. Security-sensitive testing specifics

If any part of your system has a privileged surface, a trust boundary, or a security-relevant
default, your live lab needs to prove the boundary holds under real conditions, not just that
the happy path works.

- **Every allowlist/permission gate gets exact-match testing** (§7.10): prove the narrow
  intended value is accepted, and separately prove a same-shaped-but-different value is
  rejected. A test that only proves acceptance proves nothing about scope.
- **Never weaken a default-deny or fail-closed control to make a test pass.** If a control
  correctly rejects something your test expected to be allowed, the test's expectation was
  wrong (bucket 3 in §8.7) — fix the test, not the control.
- **Assert security controls live, not assumed.** If your system claims to fail closed when
  trust state is missing/stale/invalid, or to reject a replayed/tampered message, or to
  enforce strict ordering/freshness — prove each of those, live, on a real target, as its own
  explicit negative-path stage. A control that's never actually been exercised under the
  condition it exists to guard against is an unverified claim, not a tested one.
- **Never let the harness itself become a privilege-escalation path.** If your orchestrator
  invokes privileged operations on targets, do so with explicit argument lists (never by
  constructing a shell command string that incorporates data your harness doesn't fully
  control) and validate inputs at the same rigor you'd expect of the production code path
  itself — a test harness with a security hole is still a security hole.
- **Never log or persist secrets/credential material** anywhere your evidence ledgers,
  logs, or reports end up — redact deliberately, and treat any accidental leak as requiring
  rotation of whatever leaked, not just deletion of the log line.

---

## 13. Bootstrapping this for a new project — the starter checklist

A concrete, ordered path to standing this up from nothing:

1. **Decide if you actually need this** (§1). If you don't have multi-platform, multi-target,
   or security-boundary correctness concerns that unit/CI tests can't reach, don't build this
   — extend your CI matrix instead.
2. **Enumerate your roles and platforms** (§4). Even a rough first pass at the role×platform
   grid tells you the shape of the problem.
3. **Stand up the smallest possible pipeline** (§3) against the smallest possible topology (one
   or two targets, one role each). Get Preflight → Prepare → Deploy → one real Validate stage
   → Report working end-to-end before adding anything else. Resist the urge to build the
   full stage catalog before you've proven the pipeline shape works at all.
4. **Get the data model right from day one** (§6). It is far more painful to retrofit a
   proper ledger schema onto an existing pile of ad-hoc log files than to start with one.
   Even a minimal version: a stage-status file per run, a manifest, a final result file, and
   an append-only historical ledger.
5. **Write your first few validators with the pitfalls catalog open** (§7). In particular,
   settle your remote-invocation convention (absolute paths, §7.4) and your "call in-process,
   don't shell out to a rebuild" convention (§7.2) before you have more than a couple of
   stages, because retrofitting these across a large existing stage catalog is tedious.
6. **Adopt the commit/run etiquette from day one** (§8), even while the system is small — the
   habits (two-speed runs, provenance protection, root-cause classification before patching)
   are far easier to establish early than to retrofit onto an established, sloppier workflow.
7. **Grow the stage catalog one validated stage at a time**, using the fast-inner-loop
   discipline (§8.3) throughout — never let "add ten stages, then debug all of them at once"
   happen; you'll lose the ability to tell which change caused which new failure.
8. **Add the triage ledger** (§6.5, §10) as soon as you have your first handful of recurring
   or hard-to-diagnose failures — retrofitting this after you've already forgotten several
   past diagnoses wastes the exact value it exists to provide.
9. **Add chaos/stress stages only once the golden path is reliably green** (§3, Phase 6). A
   flaky chaos suite stacked on an unreliable golden-path suite produces noise that obscures
   both.
10. **Build the dashboard/monitor last, and hold it to the read-the-same-ledger standard from
    day one** (§9) — it's tempting to build a nicer-looking dashboard that computes its own
    convenient approximations; don't.
11. **Only add AI-agent-assisted operation once the human-run discipline in §8 is solid**
    (§11) — an agent operating this system is only as trustworthy as the ledgers and
    provenance checks it's grounded against; build those first.

---

## Appendix A — Copy-adjacent schema templates

### A.1 Stage-status ledger row (tab-separated; one row per stage, upsert-by-stage-name)

```
stage_name    kind    status    return_code    log_path    summary    start_utc    end_utc
```

### A.2 Run manifest (JSON)

```json
{
  "schema_version": 1,
  "generated_at_utc": "2026-01-01T00:00:00Z",
  "invocation": "orchestrate --topology <...> --report-dir <...>",
  "mode": "full",
  "source_commit": "<VCS revision id this run is attesting to>",
  "source_clean": true,
  "selectors": {},
  "stages": [
    {
      "name": "example_validation",
      "group": "validate",
      "enabled": true,
      "synthetic": false,
      "counts_as_check": true,
      "budget_secs": 300
    }
  ],
  "node_assignments": [
    { "target_alias": "target-a", "role": "coordinator" },
    { "target_alias": "target-b", "role": "worker" }
  ]
}
```

### A.3 Final result (JSON)

```json
{
  "overall_status": "fail",
  "run_id": "run-<timestamp>-<pid>-<seq>",
  "git_commit": "abc1234",
  "run_started_utc": "2026-01-01T00:00:00Z",
  "run_finished_utc": "2026-01-01T00:12:34Z",
  "outcomes": [
    {
      "stage": "example_validation",
      "status": "pass",
      "summary": "",
      "artifacts": ["path/to/log.log"]
    }
  ]
}
```

### A.4 Historical run-matrix ledger row (CSV columns, abbreviated)

```
run_id, run_started_utc, run_finished_utc, git_commit, overall_result,
first_failed_stage, <role_a>_<platform_x>_status, <role_a>_<platform_y>_status, ...
```

### A.5 Triage/failure ledger record (JSON-lines)

```json
{
  "schema": 1,
  "id": "stub-<unique>",
  "ts_utc": "2026-01-01T00:00:00Z",
  "run_id": "run-<...>",
  "run_commit": "abc1234",
  "stage": "example_validation",
  "scope": "platform-x",
  "error": "connection reset mid-handshake",
  "patch": null
}
```

---

## Appendix B — A quick glossary (map these terms onto your own project's vocabulary)

| Term used in this document | What it generically means |
|---|---|
| Target | Any machine/device/environment under test — a VM, container, physical device, cloud instance |
| Role | A logical job a target can be assigned to play in the system under test |
| Platform | The OS/hardware/environment flavor a target represents |
| Stage | One discrete, named step in the pipeline with its own pass/fail outcome |
| Establish phase | Whatever makes independent targets into a coordinated system (discovery, trust exchange, config convergence) |
| Ledger | Any durable, structured, machine-readable record of run outcomes |
| Authoritative run | A clean run against committed source, whose result is trusted as real evidence |
| Iteration run | A fast, frequent run (possibly against uncommitted state) used only for quick feedback |
| Provenance check | The mechanism that verifies an authoritative run's source didn't change mid-run |
| Parity matrix | The role × platform grid tracking which combinations have been proven |

---

*This document is meant to be lived in, edited, and argued with — not read once and filed
away. The moment you find a new pitfall the hard way, add it to §7 before the lesson has a
chance to be forgotten and relearned.*
