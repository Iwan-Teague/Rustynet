# Windows `validate_baseline_runtime` DnsFailclosed IPv6 flake — diagnosis

Status: **FIXED, commit `e50235f9` — not yet live-re-proven.** Root cause
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

This is security/DNS-fail-closed-posture-relevant code (§4 of `CLAUDE.md`/`AGENTS.md`
non-negotiable constraints), so any actual fix here must be self-implemented and
gated (unit test + live-lab re-proof), not handed to an external model to write.

## 6. Evidence trail

- `documents/operations/live_lab_stage_triage.jsonl` — 4+ `validate_baseline_runtime`
  entries for `windows-x86-1` carrying this exact error text, each recorded with
  `patch: "none: ..."` (deferred, not yet fixed) as the launch-gate remedy.
- Investigated read-only 2026-09-05 (this session) via a background research
  agent grounded against the live repo tree at commit `ece47110` (post the
  `traffic_test_matrix` fix); no code changes made as part of this pass.
