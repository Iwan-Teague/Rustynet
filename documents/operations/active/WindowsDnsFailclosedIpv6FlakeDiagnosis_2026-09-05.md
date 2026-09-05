# Windows `validate_baseline_runtime` DnsFailclosed IPv6 flake — diagnosis

Status: **`e50235f9`'s IPv6 fix is INSUFFICIENT — reproduced live in
`run-2026-09-05-windows-28-four-fixes-proof` despite the fix being in place.**
The NRPT fix (`9e40999e`, §6) held (no NRPT drift in that run's failure). See
§7 for the live evidence and the open theory — under active investigation, do
NOT treat §5/§6 as closed. Root cause
identified by direct code reading (§2-4 below), reproduced 6 times across
recent live-lab runs (including twice while re-proving the separate
`traffic_test_matrix` fix, which blocked getting an official pass on that
stage). Separate from, and unrelated to, the `traffic_test_matrix` "Invalid
MAC" bug fixed in `WindowsTrafficTestMatrixLiveDiagnosis_2026-09-05.md` —
different stage, different mechanism.

**Fix landed:** `apply_dns_loopback` (`crates/rustynetd/src/phase10.rs:5855`)
now verifies the tunnel adapter's live IPv6 DNS state after each `netsh` set
(reusing the collector `validate_baseline_runtime` itself uses) and retries on
drift, up to `WINDOWS_DNS_IPV6_LOOPBACK_VERIFY_ATTEMPTS` (5) attempts
`WINDOWS_DNS_IPV6_LOOPBACK_VERIFY_INTERVAL` (400ms) apart, before failing
closed with a clear error if it never settles — this is exactly the §5.1
"primary" fix proposed below. §5.2 (defense-in-depth: extend the egress
IPv6-disable helper to the tunnel adapter) was NOT implemented; the §5.1 fix
alone closes the race by construction (whichever side wins, the daemon
observes and corrects it within the retry window) so §5.2 was judged
unnecessary additional surface for now. Adds
`interface_ipv6_dns_is_loopback_only` (`windows_dns_failclosed.rs`) as a
separately-testable pure helper, with 5 unit tests. Verified: `cargo fmt
--check`, `cargo clippy -p rustynetd --all-targets -- -D warnings`, `cargo
check -p rustynetd --all-targets --target x86_64-pc-windows-gnu`, and `cargo
test -p rustynetd --all-targets --all-features` (2407 passed; the one
failure, `port_mapper::pcp_request_udp_mapping_round_trip_against_fake_gateway`,
is an unrelated port-contention flake that passes clean in isolation) all
clean before landing. **Not yet re-proven live** — the next live-lab run
against this commit should confirm `validate_baseline_runtime` passes for
`windows-x86-1` without hitting this error, ideally also reaching the
official `traffic_test_matrix` pass this fix was blocking.

## 1. Symptom

`validate_baseline_runtime` intermittently fails on `windows-x86-1` (~40-50% of
runs; reproduced at least 4 times across `documents/operations/live_lab_stage_triage.jsonl`
entries for this stage) with:

```
windows-x86-1/DnsFailclosed: validation not passed — drift: interface rustynet0
(Ipv6) has non-loopback DNS server fec0:0:0:ffff::1; fail-closed posture
forbids any off-loopback resolver on a host interface
```

`fec0:0:0:ffff::1` is a legacy Windows-assigned IPv6 site-local DNS placeholder
that ships as part of new-interface bring-up on Windows, independent of
anything Rustynet configures.

## 2. Apply side — one-shot, no verify, no anti-reassert

- `apply_dns_loopback` (`crates/rustynetd/src/phase10.rs:5855-5881`): sets IPv4
  DNS to loopback via `netsh` (5862-5868), then IPv6 via
  `windows_dns_set_ipv6_loopback_args` (5869-5874; body at 9037-9048) — a
  single, literal `netsh interface ipv6 set dnsservers name=<iface>
  source=static address=::1 validate=no`. No read-back, no retry, no wait for
  the tunnel adapter to settle first.
- `apply_dns_protection` (`phase10.rs:6417-6477`): installs the firewall
  DNS-block rules, then calls `apply_dns_loopback()` once (line 6471). Its
  trait doc (611-629) confirms this runs after `backend.start()` creates the
  tunnel adapter, but nothing waits for the WireGuard-NT adapter to reach a
  steady/media-connected state before the one-shot `netsh` fires.
- `assert_dns_protection` (`phase10.rs:6479-6501`) only re-checks the 2
  firewall rules — it never re-verifies the interface's actual DNS value, so
  there is no self-healing loop anywhere in the daemon's own runtime checks.
- Adjacent infrastructure for exactly this class of problem already exists but
  is opt-in and doesn't apply to the tunnel adapter:
  - `router_discovery_enabled` / `WindowsRouterAdvertisementObservation`
    (`crates/rustynetd/src/windows_dns_failclosed.rs:101-121`) +
    `evaluate_router_advertisement_suppression`, gated behind
    `--enforce-ra-suppression` (`main.rs:2731-2769`) — this **detects** RA-driven
    drift and fails closed on a missing observation; it does not prevent
    anything.
  - `windows_ipv6_egress_disable_args` / `_rollback_args`
    (`phase10.rs:9244-9304`) disable IPv6 router-discovery/advertise
    processing — but only on the **egress/underlay** adapter, never on the
    tunnel adapter itself, where the drift is actually observed.

## 3. Validator side — one-shot, zero settle time, live OS query

- `ValidateBaselineRuntimeStage::dependencies()` = `[EnforceBaselineRuntime]`
  (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/validate_runtime.rs:138`)
  — runs immediately once the daemon-(re)start stage reports success, with no
  delay.
- Dispatch: `node_adapter.rs:614-616` →
  `validate_windows_dns_failclosed` (`.../adapter/dns_failclosed.rs:72-85`) — one
  SSH round-trip running `windows-dns-failclosed-check --no-fail-on-drift`.
  No retry/backoff anywhere in this path or its caller
  (`bounded_parallel_map_cancellable`, `validate_runtime.rs:162-188`).
- The check evaluates a **live** PowerShell-collected snapshot
  (`windows_dns_failclosed.rs:136-218`; the exact error text is at 157-160) —
  whatever Windows reports at that instant is the verdict. The
  RA-suppression evaluator is **not** invoked here (`dns_failclosed.rs:78`
  passes only `--no-fail-on-drift`).

## 4. Hypothesis (not yet live-confirmed)

A classic apply/check race with no synchronization on either side. Nothing
waits for the freshly-created tunnel adapter to settle before the daemon's
one-shot `netsh` DNS-loopback set; nothing re-verifies the setting afterward;
the validator checks live OS state immediately with zero grace period.
Windows populates the tunnel adapter's legacy IPv6 DNS placeholder
(`fec0:0:0:ffff::1..3`) as part of new-interface bring-up (IP Helper / NCSI),
independent of the opt-in RA-suppression path. Whichever side — our `netsh`
set, or Windows' own interface-init — finishes last on a given run decides
pass or fail, which is consistent with the observed ~40-50% flip rate.

## 5. Proposed fix (not implemented — scope for a future session)

1. **Primary:** make `apply_dns_loopback` (`phase10.rs:5855`) verify-then-retry
   — after the `netsh` set, re-read the interface's IPv6 DNS servers (reuse
   the collector behind `evaluate_windows_dns_failclosed_snapshot`) and
   re-apply on a short bounded poll (~3-5 attempts, 250-500ms apart) before
   returning `Ok`.
2. **Defense in depth:** extend the existing
   `windows_ipv6_egress_disable_args`-style `netsh` call (`phase10.rs:9251-9262`)
   to also target `self.interface_name` (the tunnel adapter), not just egress —
   this prevents anything from re-sourcing the tunnel interface's IPv6 config
   after the daemon sets it.
3. Do **not** rely on wiring `--enforce-ra-suppression` alone as the fix — it
   only detects the drift and fails closed on a missing observation
   (`main.rs:2726-2730`); wiring it without the retry/suppression above would
   just relabel the same race as a different failure mode.

## 6. A second instance of the same race, on the NRPT rule — also fixed (`9e40999e`)

`run-2026-09-05-windows-27-three-fixes-proof` was the FIRST run ever to get
past the §1 IPv6 symptom (thanks to `e50235f9`) — and the very next run hit a
**different** `DnsFailclosed` drift on the same stage:

```
windows-x86-1/DnsFailclosed: validation not passed — drift: no NRPT rule
covers the . root namespace with loopback name servers; unqualified lookups
would resolve via the host's default DNS path
```

This confirms the two symptoms were never masking each other (the orchestrator
joins ALL `drift_reasons` with `"; "` —
`crates/rustynet-cli/src/vm_lab/mod.rs:20228` — so if both had ever coexisted,
both would have appeared in one message) — this is a genuinely separate
occurrence of the identical mechanism: `apply_dns_loopback`'s NRPT step
(`phase10.rs:5930-5934` at the time) added the root-namespace rule via a
single fire-and-forget `reg.exe add`, with no read-back, and
`Get-DnsClientNrptRule` (WMI-backed, per `windows_dns_failclosed.rs:498`) can
lag a registry write by a beat just as `Get-DnsClientServerAddress` could lag
a `netsh` set.

**Fix landed:** `9e40999e`. Applied the exact same verify-then-retry pattern
to the NRPT step: re-read the live NRPT rule set after each `reg.exe add`
(reusing `nrpt_rules_cover_root_namespace`, newly made `pub` in
`windows_dns_failclosed.rs`) and retry on drift, up to 5×400ms, before failing
closed. fmt/clippy/Windows-cross-compile/full test suite all verified clean.
Not yet live-re-proven.

**How to apply if a THIRD instance of this pattern turns up:** `apply_dns_loopback`
now has two verify-then-retry loops (IPv6, NRPT) sharing
`WINDOWS_DNS_LOOPBACK_VERIFY_INTERVAL`; if another `DnsFailclosed` drift
category starts appearing after these two are exhausted, look for the same
shape first — an `apply_*`/`run_reg_success`/`run_netsh_success` call in this
function with no corresponding read-back — before assuming a new mechanism.

This is security/DNS-fail-closed-posture-relevant code (§4 of `CLAUDE.md`/`AGENTS.md`
non-negotiable constraints), so any actual fix here must be self-implemented and
gated (unit test + live-lab re-proof), not handed to an external model to write.

## 7. Evidence trail

- `documents/operations/live_lab_stage_triage.jsonl` — 4+ `validate_baseline_runtime`
  entries for `windows-x86-1` carrying this exact error text, each recorded with
  `patch: "none: ..."` (deferred, not yet fixed) as the launch-gate remedy.
- Investigated read-only 2026-09-05 (this session) via a background research
  agent grounded against the live repo tree at commit `ece47110` (post the
  `traffic_test_matrix` fix); no code changes made as part of this pass.

## 8. `e50235f9`'s fix reproduced live as INSUFFICIENT — open investigation

`run-2026-09-05-windows-28-four-fixes-proof` (commit `5933f37a`, includes all
four fixes landed this session including `e50235f9` and `9e40999e`) failed
`validate_baseline_runtime` with the EXACT §1 symptom again:
`interface rustynet0 (Ipv6) has non-loopback DNS server fec0:0:0:ffff::1`.
The NRPT fix held — this run's failure carried no NRPT drift, unlike
run-27's — so §6 is not implicated here.

**What the daemon's own log shows for this run:**

```
1788602595718 [INFO] rustynetd::phase10: windows dns loopback apply: tunnel interface='rustynet0' resolver=127.0.0.1:53
1788602605054 [INFO] rustynetd::daemon: rustynetd startup: control + privileged pipe servers spawned; entering reconcile loop
```

No `"IPv6 loopback settled on attempt N/5"` line appears — meaning either the
verify-then-retry loop's FIRST attempt already read back as loopback-compliant
(so nothing logged, since that log line only fires when `attempt > 1`), or
the ~9.3s gap between these two lines is entirely `apply_dns_loopback`'s own
work (IPv4 set, IPv6 set+verify, NRPT add+verify, each involving a
`powershell.exe` collector invocation) with no retries needed on either loop.
No `DnsApplyFailed` error appears either, so `apply_dns_loopback` returned
`Ok` — the daemon's OWN check, at the time it ran, found the interface
compliant. **Yet `validate_baseline_runtime`, running some seconds later
(after `enforce_daemon`'s `windows_tunnel_ip_readiness_fragment` — up to 90s,
usually fast — resolves and the orchestrator's own SSH round-trip completes),
found it drifted again.**

Two open theories, not yet distinguished by direct evidence:

1. **Vacuous-pass bug in the verify helper itself.** `interface_ipv6_dns_is_loopback_only`
   returns `true` when the snapshot has **no entry at all** for the interface
   (deliberately, for interfaces the collector has never heard of — see its
   own test `interface_ipv6_dns_is_loopback_only_accepts_unknown_interface`).
   If, at the exact moment `apply_dns_loopback`'s verify snapshot is taken,
   `rustynet0` genuinely has **zero** DNS-server entries recorded yet (neither
   our `::1` set nor Windows' placeholder have been picked up by
   `Get-DnsClientServerAddress` at that instant), the helper would report
   "compliant" on a state that is really "undetermined", declaring victory
   before the actual race has resolved either way.
2. **A later Windows-triggered event re-populates the placeholder.** The
   `apply_dns_loopback` call runs early, right after `backend.start()` creates
   the tunnel adapter (per the `apply_dns_protection` trait doc, §2) — but the
   adapter may not yet have its mesh IP address bound at that point (`enforce_daemon`
   separately polls for that via `windows_tunnel_ip_readiness_fragment`, up to
   90s, AFTER `start_daemon` returns). If Windows re-runs its own
   network-location/interface-classification logic specifically when an
   interface transitions from "up, no address" to "up, has address" — and that
   logic is what (re-)writes the legacy IPv6 DNS placeholder — then the
   verify-then-retry loop's window is simply too early to ever observe the
   real triggering event, no matter how many attempts it budgets.

**Both theories point the same direction:** a single verify pass immediately
after `apply_dns_loopback`'s own `netsh` calls cannot close this race if the
thing that re-introduces drift happens **later**, driven by tunnel-IP
assignment rather than interface creation. The next step needing DIRECT live
evidence (not yet done): re-run with continuous polling of `rustynet0`'s IPv6
DNS state (2-3s interval) spanning the whole `enforce_baseline_runtime` →
`validate_baseline_runtime` window, correlated against the moment the tunnel
adapter actually receives its mesh IP, to see whether the placeholder
reappears (a) immediately (vacuous-pass theory) or (b) specifically at/after
IP assignment (later-trigger theory) or (c) something else. Do not attempt a
fifth fix before that evidence exists — the last four fixes in this session
were each landed on solid direct evidence; this one should be too.

## 9. Theory B confirmed — root cause found, fifth fix landed (`923f2f9b`)

The evidence came in from two directions at once:

**Code reading.** `backend.start()`'s own readiness wait
(`wait_for_tunnel_ready`, `rustynet-backend-wireguard/src/windows_command.rs:163-188`)
only confirms `wg show <tunnel>` returns non-empty — the adapter is attached
and queryable — and its own doc comment explicitly says the adapter "may
still be initialising." It does **not** wait for an IP address to bind. The
only place that DOES wait for the address (`windows_tunnel_ip_readiness_fragment`,
`windows_install.rs:912`, up to 90s) lives on the **lab orchestrator side**,
called from `enforce_daemon` well AFTER `apply_dns_loopback` already ran
inside the daemon's own `apply_dataplane_generation`. A real end-user install
never runs that orchestrator wait at all — meaning this gap is a live
daemon-side defect, not a lab-timing artifact.

**Live evidence, twice in one run.** The tightly-instrumented diagnostic run
(`run-2026-09-05-windows-29-dns-race-diagnostic`) polled `rustynet0`'s IPv6
DNS servers and IPv4 address every 2s and caught the mechanism directly,
TWICE:

```
[10:23:40] DNS6=fec0:0:0:ffff::1,...  IP4=100.64.0.1     <- same poll cycle
[10:23:44] DNS6=::1                                       <- daemon corrects it
...
[10:23:57] DNS6=fec0:0:0:ffff::1,...  IP4=100.64.0.1     <- same poll cycle, again
[10:24:07] DNS6=::1                                       <- daemon corrects it again
```

The placeholder appears in the **same poll cycle** as the mesh IP —
confirming Windows re-writes the interface's default IPv6 DNS as a side
effect of the address-bind event itself, which happens strictly AFTER
`apply_dns_loopback`'s own verify-then-retry loop already ran and returned
`Ok` (that loop runs immediately after `backend.start()`, before the address
exists). This is why §5's fix could "succeed" on its own terms and still lose
the race: it was verifying a state that had not yet been perturbed by the
event that perturbs it.

**Fix landed:** `923f2f9b`. `apply_dns_loopback` now calls a new
`wait_for_tunnel_ip_address` FIRST, before touching DNS at all — polling
`Get-NetIPAddress` (via a new `WINDOWS_PS_GET_TUNNEL_IPV4_ADDRESS` constant,
deliberately `SilentlyContinue` so an unbound address reads as empty rather
than throwing) for up to 30 attempts × 500ms (15s), failing closed with a
clear error if the address never appears. This makes the daemon's own DNS
set happen strictly AFTER Windows' address-triggered rewrite, closing the
race by construction instead of trying to out-retry it. Unit-tested
(script-shape assertion), fmt/clippy/Windows-cross-compile/full test suite
all verified clean. **Not yet live-re-proven** (the diagnostic run that
produced this evidence used the PRE-fix code, as intended — it needed to
observe the unfixed mechanism).
