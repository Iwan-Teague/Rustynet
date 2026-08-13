# Guest clock skew is invisible until it breaks something else — plan — 2026-08-13

**Status: PLAN, unreviewed.** Diagnosed from a live 151-minute failure.

## 0. What happened

`roles-20260813p` failed after **151 minutes** (normal: ~17) with:

```
enforce_baseline_runtime — rocky-utm-1: remote command failed (exit 1):
  daemon socket /run/rustynet/rustynetd.sock failed to become available after 40 attempts
  (last_state=No such file or directory)
  daemon: rustynetd startup: daemon exited fatally: invalid config:
          auto tunnel preflight failed: auto-tunnel bundle is future dated
```

Root cause, measured: `rocky-utm-1`'s clock was **8455 s (2 h 20 m 55 s) behind the host**, so a
correctly-issued bundle read as future-dated and the daemon refused it.

**The daemon is right.** A future-dated signed bundle is a tamper signal and §10.1 says fail
closed. Nothing about that behaviour should change.

## 1. Why the diagnosis was expensive

Three properties combined to hide a trivial fault:

1. **The visible error names the wrong subsystem.** The stage reports a socket that never
   appeared. The word "clock" appears nowhere; the actual reason is one line deeper, inside a
   captured daemon log tail.
2. **It costs 151 minutes to learn it.** The socket wait retries 40 times per node before the
   stage gives up, and every downstream stage then cascade-skips.
3. **The guest itself reports that it is fine.** `timedatectl` said
   `System clock synchronized: yes` / `NTP service: active`. All four chrony sources agreed on
   `-8455s`, but **none was selected** (no `^*`), so the offset was measured and never applied.
   `chronyc makestep` returned `200 OK` and changed nothing. `hwclock` agreed with the wrong
   time, so the RTC was genuinely off rather than this being a display artifact.

A guest that lies about its own sync state is exactly why the check must be **host-side
comparison**, not a query of the guest's opinion.

## 2. The change

Add a clock-skew check to `preflight` (`stage/preflight.rs`), which already validates
report-dir writability and network-profile immutability before anything is deployed.

For each node: read the guest's `date -u +%s` over the existing shell seam, compare against the
host's, and fail the stage when `|skew|` exceeds a bound — naming the alias, the measured skew,
and the fix.

### Why preflight and not the daemon

The daemon already fails closed correctly. Duplicating the judgement there would be a second
policy to keep in sync. Preflight is where the lab establishes that the fleet is fit to run, and
it costs one SSH round trip per node.

### The bound

Proposed **60 s**, to be challenged in review. Reasoning: bundle max-age windows in this lab are
300 s and 86400 s, so a skew under a minute cannot flip a freshness decision, while the observed
fault was 8455 s — 140x the bound. A tight bound risks redding a healthy fleet over ordinary NTP
jitter; a loose one lets a fault through. Review should say whether 60 is right, and whether the
bound should relate to the *smallest* max-age window in play rather than be a constant.

### Fail or warn

**Fail.** A warning reproduces the current situation: the information exists but nobody acts on
it until something else breaks. The counter-argument — that a skewed clock might not affect a
run that issues no bundles — is weak, because every run issues bundles in setup.

## 3. Blast radius

- One extra SSH round trip per node in preflight. Negligible against a ~17-minute run.
- A fleet with a genuinely skewed guest now fails in **seconds, at preflight**, instead of
  ~151 minutes at `enforce_baseline_runtime`. That is the point.
- Risk: if the bound is too tight, a healthy fleet reds. §4.2 pins the lower edge.
- No wire format, no daemon change, no bundle change.

## 4. Tests, each with the mutation that proves it discriminates

1. A node skewed beyond the bound fails preflight, and the message names the alias and the
   measured skew. *Mutation:* drop the comparison → passes → fails.
2. A node within the bound passes. *Mutation:* set the bound to 0 → a healthy fleet reds → fails.
   Guards the lower edge.
3. The message names the remedy, not just the fault. *Mutation:* reduce it to "clock skew" →
   fails. The whole defect was a message that did not lead anywhere.
4. Skew is measured host-vs-guest, NOT read from the guest's own sync status. *Mutation:* assert
   on `timedatectl`'s "synchronized" field → the observed fault reports healthy → fails. This is
   the test that encodes the actual lesson.

## 5. Open questions for review

1. Is 60 s right, and should the bound derive from the smallest max-age window rather than be a
   constant?
2. Where exactly in `preflight` — before or after the network-profile check? Ordering matters
   only for which error a doubly-broken fleet reports first.
3. Windows guests: `date -u +%s` is not available. Does the shell seam already abstract this, or
   does the check need a per-platform command? If the latter, is a Linux/macOS-only check
   acceptable, or does that re-create a silent gap for Windows?
4. Should the check also record each node's skew into the run artifact even when it passes, so a
   slow drift is visible before it crosses the bound?
5. Is there an existing host-vs-guest comparison helper to reuse rather than writing a fourth
   variant?

## 6. Definition of done

A skewed guest fails preflight in seconds with a message naming the alias, the skew and the fix;
every test above is mutation-proven; §7 gates pass; and the run that exposed this is re-run to
confirm the fleet passes.
