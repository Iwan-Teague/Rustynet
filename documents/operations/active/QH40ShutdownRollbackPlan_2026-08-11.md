# QH-40 — the macOS shutdown rollback fails and the process still reports success — plan — 2026-08-11

> **REVIEWED AND REFUTED 2026-08-11. DO NOT IMPLEMENT C1 OR C2 AS WRITTEN.**
> §0's correction of QH-40 survived and should land. The remedy did not: this plan
> replaced one wrong mechanism with another.
>
> 1. **The root cause is not the 20 ms race.** The same signature appears at ~25 distinct
>    shutdowns from 2026-07-03 to 2026-08-11 — a 20 ms margin does not recur deterministically
>    for five weeks. Decisively: the FIRST rollback step failed with `truncated frame header`
>    while the helper was still **alive** (it died 1.019 s later); only later steps got
>    `Connection refused`. Both QH-40 and this plan quoted that log line with its own
>    explanatory clause cut — the daemon's own diagnostic says a truncated frame "is usually
>    the helper's own I/O timeout elapsing while it runs a privileged command". The same
>    failure occurs on `bootstrap_apply_failed` and `membership_reconcile_failed`, paths with
>    **no teardown in flight at all**.
> 2. **C1's 30 s bound is unreachable.** launchd logs `scheduling cleanup in 5 sec after
>    sending Terminated: 15`, and the daemon plist declares no `ExitTimeOut`, so the 5 s
>    default governs — while the helper runs with `--timeout-ms 30000`, 6x that budget. A poll
>    would observe "job gone" *because of the SIGKILL* and report success.
> 3. **C2 introduces a key-custody regression.** Returning `Err` at the shutdown site skips
>    `scrub_runtime_wireguard_key_after_bootstrap` (`daemon.rs:10938`), leaving plaintext
>    WireGuard key material on disk — a §4 violation created by the fix. It would also print
>    `rustynetd startup failed` on a shutdown path.
> 4. **§4's severity call is refuted by the log line this plan itself quoted.** The elided
>    clause includes `rollback nat forwarding: rollback failed: restore macOS
>    net.inet.ip.forwarding failed`, and `phase10.rs:3316` confirms rollback is what restores
>    that sysctl to 0. So a failed rollback leaves **host IP forwarding enabled and exit NAT
>    rules installed** — strictly MORE open, not "broken-closed". §10.7 (exit NAT residue is a
>    release blocker) applies directly and QH-40's HIGH severity is if anything understated.
>
> **What a correct attempt must start from:** the helper I/O timeout, not the teardown; the
> 5 s launchd SIGKILL ceiling as a hard constraint on any wait; and the fact that nothing on
> the macOS launchd path observes the daemon's exit code at all (`KeepAlive` is unconditional;
> the only `daemon_exit_code` consumer is Windows-only, `bootstrap/windows.rs:781`). A
> zero-schema durable signal may already exist — the residue itself is readable, and
> `macos_exit_nat_lifecycle.rs:60` already reads `net.inet.ip.forwarding`.

**Status: PLAN — REFUTED, superseded by the note above.** Written against `HEAD = a419e77e`, clean tree. Every claim was
produced by reading the code or re-querying the guest's unified log; the command is named so
a reviewer re-runs rather than trusts.

## 0. QH-40's stated mechanism is WRONG, and it is my error

The entry says:

> "launchd signalled `com.rustynet.privileged-helper` (pid 16607) at `01:01:18.984` and
> `com.rustynet.daemon` (pid 16611) at `01:01:18.985` — the helper **one millisecond
> earlier**."

**That compared the helper's SIGTERM to the daemon's EXIT.** Re-derived from the guest with a
bounded query (`log show --predicate 'process == "launchd"' --start "2026-08-11 01:01:15"
--end "2026-08-11 01:01:22"`):

| guest-local | event |
| --- | --- |
| `01:01:17.965` | **daemon** bootout + `signaled service: Terminated: 15` |
| `01:01:18.984` | **helper** bootout + SIGTERM, `exited due to SIGTERM … ran for 56531ms` |
| `01:01:18.985` | **daemon** `exited due to exit(0), ran for 56524ms` |

The daemon was signalled **1.019 s BEFORE** the helper. The teardown order is **correct**, and
our own scripts already encode it deliberately — `Install-RustyNetMacosService.sh:524-531` and
`Bootstrap-RustyNetMacos.sh:754-758` both boot the daemon out first, then the helper.

**The real defect is a fixed sleep losing a race by 20 milliseconds:**

```sh
launchctl bootout system/com.rustynet.daemon || true
sleep 1                                    # <-- daemon took 1.020 s to exit
...
launchctl bootout system/com.rustynet.privileged-helper || true
```

The daemon's graceful shutdown ran for **1.020 s**; the script waited **1 s**. The helper was
torn down 1 ms before the daemon finished, so the daemon's rollback lost its privileged
transport mid-flight. That is why every rollback path failed:

> `rollback dns protection: rollback failed: firewall apply failed: … privileged helper
> response read failed: truncated frame header` … `backend shutdown: … privileged helper
> connect failed (…rustynetd-privileged.sock): Connection refused` … `exit-mode rollback
> failed` … `cleanup failed` … `interface cleanup failed`

A reviewer who accepts the entry's framing would "fix" the ordering, find it already correct,
and conclude there is no bug. Correcting the entry is part of this change.

## 1. The second half is real and is the §4 violation

Independently of the race, the shutdown path **discards** a failed rollback
(`daemon.rs:10772-10778`):

```rust
if shutdown_signals.requested() {
    if let Err(err) = runtime.controller.shutdown() {
        log::error!("unix shutdown-signal-triggered controller shutdown encountered errors (best-effort): {err}");
    }
    break;
}
```

`Phase10::rollback` does its job — it accumulates every failure and returns
`SystemError::RollbackFailed` (`phase10.rs:5560-5563`). The caller logs it, labels it
"best-effort", and breaks; the process then falls off the end of `main` and exits **0**.
(`main.rs:88-96` is the *startup* failure path — `rustynetd startup failed` — and never runs
on this path.) So a node that failed to remove its firewall, DNS protection, exit-mode and
interface state reports a clean stop, and nothing downstream can tell.

**This is exactly the class RN-03 already settled elsewhere.** `force_fail_closed_or_restrict`
(`daemon.rs:9628-9640`) exists precisely to "surface the enforcement failure instead of
discarding it — record a PERMANENT restriction so the node never silently treats a failed
fail-close as success", and its comment reasons carefully about not rolling back further
because that would fail open. **The shutdown path is the same shape and did not get the same
treatment.** Do not invent a new mechanism; the norm exists.

## 2. Constraint discovered while grounding — it shapes the fix

`KeepAlive = true` (unconditional, not `SuccessfulExit`) in
`scripts/launchd/com.rustynet.daemon.plist:57-58`. So **launchd already restarts the daemon on
any exit, and a non-zero exit code changes nothing about restart behaviour.** A non-zero exit
is therefore honest but nearly inert operationally — it is visible in the unified log and to a
script that inspects it, and nowhere else. Any proposal resting on "exit non-zero so something
notices" must say *what* notices.

The durable alternative — persist a "previous shutdown left residue" marker so the next start
fails closed — is stronger but is **not free**: `persist_state` writes only
`{timestamp_unix, peer_ids, selected_exit_node, lan_access_enabled}` (`daemon.rs:9126-9132`),
and `restriction_mode` is in-memory only, so this needs a persisted field and a schema
decision.

## 3. The change

### C1 — wait for the daemon to exit, do not sleep a guess

In both teardown scripts, replace the fixed `sleep 1` after the daemon bootout with a bounded
poll on `launchctl print system/com.rustynet.daemon` until the job is gone, then boot the
helper. Bound it (say 30 s) and, on timeout, proceed **and say so on stdout** — the script
must not hang forever, and a timeout is itself a finding.

This is the fix that eliminates the observed failure. It is small, it is verifiable against
the measured 1.020 s, and it removes the 20 ms cliff rather than widening it to a larger
guess. **Do not simply raise `sleep 1` to `sleep 5`** — that re-creates the same defect with a
bigger number and no signal when it is exceeded.

### C2 — a failed shutdown rollback must not read as a clean stop

Minimum: keep the existing `log::error!`, and additionally exit non-zero on
`RollbackFailed`, per §2's honesty caveat about what that does and does not achieve.

**Open decision for the reviewer, deliberately not taken here:** whether to add the durable
marker so the *next* start fails closed. Arguments both ways — it is the true fail-closed
behaviour and matches RN-03's intent, but it costs a persisted-state schema change, and a
node that cannot be restarted without operator action is itself an availability hazard in a
lab that reboots guests routinely. **Recommendation: C2-minimum now, durable marker specified
and deferred**, because C1 removes the case that actually fires today.

### C3 — correct QH-40's text

Replace the ordering claim with the race, keeping the original visible per this register's
norm on retracted findings.

## 4. Residue semantics — state the uncertainty rather than assume

Leftover firewall/DNS rules after a failed rollback **block** traffic rather than admit it, so
the residue is closer to broken-closed than fail-open. That makes it an availability and
correctness problem, and §10.7 treats exit-NAT residue as a release blocker — but this plan
should not claim it is a security hole without establishing that. What is certain is the
**reporting** defect: the node cannot tell anyone. That is what C2 fixes.

## 5. Tests, each with the mutation that proves it discriminates

1. `wait_for_daemon_exit` returns as soon as the job is gone. *Mutation:* return
   unconditionally after one poll → a still-running daemon reads as exited → fails.
2. It bounds its wait and reports a timeout distinctly from success. *Mutation:* loop forever
   → test times out.
3. Neither script boots the helper before the daemon. *Mutation:* swap the two blocks → fails.
4. Neither script contains a bare `sleep` between the daemon bootout and the helper bootout.
   *Mutation:* reinstate `sleep 1` → fails. (This is the regression that occurred; pin the
   shape, not just the behaviour.)
5. A `RollbackFailed` from `controller.shutdown()` on the signal path produces a non-zero exit.
   *Mutation:* swallow the error as today → fails.
6. A successful shutdown still exits 0. *Mutation:* always exit non-zero → fails.

**Live acceptance:** re-run the plist reload on `macos-utm-1` and confirm the daemon's
rollback completes — no `privileged helper connect failed` in the shutdown window — using the
same bounded `log show` query as §0. An unbounded query mixes in older daemon instances and
has already produced a wrong conclusion in this repo.

## 6. Definition of done

All §7 gates green; each test mutation-proven; QH-40 corrected with the original claim left
visible; and §0's timeline reproducible by the bounded query given there.
