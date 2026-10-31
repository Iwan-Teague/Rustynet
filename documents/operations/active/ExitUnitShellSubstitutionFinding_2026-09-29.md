# PF-3: the exit unit's forwarding check never runs (2026-09-29)

**Status.** Product finding, CONFIRMED live on katana (u20 and u21) and with a throwaway systemd probe unit. Fix: fleet lane b55, independently reviewed before landing.

## What happens

`scripts/systemd/rustynet-exit.service` line 30 was:

```
ExecStartPost=/usr/bin/test "$(/usr/sbin/sysctl -n net.ipv4.ip_forward)" = "1"
```

systemd does not run Exec lines through a shell, so `$(...)` is never substituted. systemd reads `$(` as an environment variable reference, logs "Invalid environment variable name evaluates to an empty string", and `test` receives too few arguments (`status=2/INVALIDARGUMENT`). The post-start check therefore fails on every start, whatever the forwarding state, and `systemctl start rustynet-exit.service` fails.

## Impact

`rustynet role set exit` deploys and starts this unit, so a Linux node cannot become an exit through the product path. Before PF-2 the unit template was read from a CWD-relative path, which usually failed first and hid this bug; once PF-2 embeds the templates, every exit deployment reaches it. In the live lab it surfaced as the exit-demotion restore failing at `systemctl start rustynet-exit.service` (katana-u20 and katana-u21).

It fails closed (no exit starts), so there is no exposure, but the exit role is unusable on Linux.

## Fix

The line becomes:

```
ExecStartPost=/bin/sh -c 'test "$$(/usr/sbin/sysctl -n net.ipv4.ip_forward)" = "1"'
```

`$$` is systemd's escape for a literal `$`, so the shell performs the substitution. The check still fails closed: empty or `0` output fails the unit. The unit's hardening options were kept, and a probe unit with the same hardening passed at forwarding 1 and failed at forwarding 0.

A new test in `crates/rustynet-cli/src/ops_install_systemd.rs` parses every Exec line of every unit under `scripts/systemd` and rejects shell syntax (`$(`, backticks, `&&`, `||`, `;`, `|`, redirects) outside an explicit `sh -c`. A second test fails if a unit is added to the directory without being added to the guard's list. `systemd-analyze verify` accepts the broken line, so it cannot be the guard.

An audit of all 12 units and timers found no other instance.

## Live proof

On katana guest katana-exit-1, the product install path (`rustynet ops install-systemd-exit`, which `role set exit` runs as DeployExitService) was run with each unit. The guest's journal shows both:

| When (UTC) | Unit | Result |
|---|---|---|
| 2026-09-29 17:42:54 (katana-u21 restore) | old line | `Failed with result 'exit-code'`, `Failed to start rustynet-exit.service` |
| 2026-09-30 00:17:49 (after katana-u22, same guest, fixed tree) | fixed line | `net.ipv4.ip_forward = 1`, `Finished rustynet-exit.service`; install exit 0, `ActiveState=active Result=success` |

The unit was uninstalled afterwards (`--uninstall`, `LoadState=not-found`). Note that the katana-u22 run's `exit_demotion_residue_validation` pass is not evidence for this fix: that stage's version at this commit does not run `role set exit`, and the unit was not installed during the run.

## Why not a Rustynet subcommand for the check

No existing subcommand reads a sysctl. Adding one would add a CLI surface for a one-line check, and the daemon already reads `/proc/sys` directly for its own logic. The shell form keeps the check inside the unit.

## Evidence

- Lane report and run log: fleet lane rustynet-b55-pf3-exit-unit-execstartpost.
- Review: charter/reviews/REVIEW-pf3-exit-unit-2026-09-29.md.
- Live failure: triage stubs for katana-u20 and katana-u21, stage `exit_demotion_residue_validation`.
