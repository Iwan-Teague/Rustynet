# Linux MTU Privileged-Helper Allowlist Gap: Diagnosis and Fix Plan (2026-07-21)

**Status: diagnosed and confirmed live. Fix not yet implemented.**

## 1) Symptom

`enforce_baseline_runtime` fails on every Linux lab guest. Confirmed on Fedora
(`fedora-utm-1`, 192.168.64.103) via live `journalctl -u rustynetd.service`, and the run-matrix
evidence (`documents/operations/live_lab_node_stage_results.csv`) shows the identical failure on
Ubuntu and Rocky in the same recent runs. Recorded error:
`"Job for rustynetd-managed-dns.service failed because the control process exited with error
code."` This is not caused by anything in the concurrent security-audit / A4-attestation /
rollback-watermark / branch-consolidation work — that work is documented separately in
[`SecurityAuditAndMainConsolidation_2026-07-21.md`](./SecurityAuditAndMainConsolidation_2026-07-21.md)
and none of it touches the files implicated here.

## 2) Root cause, confirmed live and by direct code reading

Commit `fef40bb` ("Add DPLPMTUD path-MTU state machine and fix never-set tunnel MTU — FIS-0027
Phase 1+2") is an ancestor of `8f957f5` (already `main`'s tip before the unrelated session's work
began) — it predates and is unrelated to that work. It added a new privileged command to the Linux
WireGuard backend's bring-up sequence, `crates/rustynet-backend-wireguard/src/linux_command.rs:197-210`,
run right after interface creation and before `link set up`:

```rust
if let Err(err) = self.runner.run(
    "ip",
    &[
        "link".to_owned(),
        "set".to_owned(),
        "mtu".to_owned(),
        SAFE_BRINGUP_TUNNEL_MTU.to_string(),
        "dev".to_owned(),
        self.interface_name.clone(),
    ],
) {
    let _ = self.remove_interface();
    return Err(err);
}
```

`SAFE_BRINGUP_TUNNEL_MTU: u16 = 1420` is defined at `linux_command.rs:24`. The resulting argv is
exactly `["link", "set", "mtu", "1420", "dev", "<interface>"]`.

`crates/rustynetd/src/privileged_helper.rs`'s `validate_ip_args` (the argv-only allowlist every
privileged `ip` invocation must pass — `CLAUDE.md` §4, "argv-only exec for helpers, strict input
validation") was never updated for this new schema. Its `link set` entries (lines 1865-1931) are
only:

```rust
["link", "set", "up", "dev", interface] if is_interface_name(interface) => Ok(()),
["link", "set", "down", "dev", interface] if is_interface_name(interface) => Ok(()),
```

No `mtu` entry exists anywhere in the match, so the new command falls through to the final
`_ => Err("unsupported ip argument schema")` arm — rejected every time, on every Linux host,
deterministically. Not a race, not flaky timing: a 100%-reproducing allowlist gap.

### The cascade (confirmed live in the journal)

1. Bring-up's MTU-set step is rejected → `linux_command.rs`'s error arm calls
   `self.remove_interface()` and returns `Err` → the interface never comes up.
2. The daemon's reconcile loop retries the same doomed operation every ~1s, logging
   `rustynetd: restrict_recoverable: reconcile dataplane apply failed: backend error: Internal:
   privileged helper ip invocation failed: unsupported ip argument schema` repeatedly.
3. After 5 consecutive failures it crosses the failure threshold: `rustynetd: restrict_permanent:
   reconcile failure threshold exceeded: N` — the tunnel is locked down permanently for that
   daemon instance.
4. `rustynet0` never exists.
5. `rustynetd-managed-dns.service` (`ExecStart=/usr/local/bin/rustynet ops
   apply-managed-dns-routing`, `BindsTo=rustynetd.service`) calls
   `wait_for_managed_dns_interface(interface, Duration::from_secs(20))`
   (`crates/rustynet-cli/src/main.rs`, `execute_ops_apply_managed_dns_routing`, ~line 10737-10786;
   `MANAGED_DNS_ROUTING_INTERFACE_WAIT_SECS = 20`), which times out because the interface genuinely
   never appears.
6. The DNS unit's oneshot `ExecStart` process exits non-zero → systemd reports "control process
   exited with error code" → that is the literal `enforce_baseline_runtime` stage failure.

## 3) What "fixed" means, and why the fix must take this exact shape

Adding an allowlist entry is a **capability grant** to whatever compromised or buggy code might one
day call the privileged helper. The correct fix is the narrowest grant that satisfies what the
caller *actually* sends today — not the widest type-range that happens to compile.

**Rejected approach: accept any numeric MTU** (e.g. `mtu.parse::<u16>().is_ok()`). This would be
over-provisioning: `linux_command.rs` only ever sends the exact literal `SAFE_BRINGUP_TUNNEL_MTU`
(1420) today — FIS-0027 Phase 1+2, which is all that's shipped. Phase 3 (described in
`documents/operations/active/FableIntelligentSystemsProposals_2026-07-01.md`, not yet implemented)
will eventually replace this static value with a dynamically-measured per-path MTU from the
`path_mtu.rs` DPLPMTUD search — *when that lands* is the correct time to widen this allowlist entry
to a validated, bounded range (RFC 8899's search space is realistically ~1280-1500, nowhere near
the full `u16` range), decided deliberately at that point. A compromised daemon that could set an
arbitrary MTU today would gain a real (if narrow) local-DoS/fragmentation-adjacent capability for
zero present-day benefit — no caller needs it yet.

**Rejected approach: cryptographic signature/verification of the MTU value.** Signing defends
against *externally-sourced* data (a peer's key, a signed membership update) where the signer is a
different trust domain than the verifier. The MTU value is not external data — it's a constant the
daemon's own code already holds, inside the same trust boundary the privileged helper exists to
contain if that daemon is compromised. A compromised daemon could sign a bad value exactly as
easily as an honest one; signing would not move the actual security boundary, which is (and should
remain) the allowlist match itself. No new crypto/protocol machinery belongs here (`CLAUDE.md` §3).

**The correct fix: match the literal constant, not a type range**, reusing the `is_interface_name`
check already used by the sibling `link set up/down` entries:

```rust
["link", "set", "mtu", mtu, "dev", interface]
    if *mtu == rustynet_backend_wireguard::SAFE_BRINGUP_TUNNEL_MTU.to_string()
        && is_interface_name(interface) =>
{
    Ok(())
}
```

(Match the surrounding arms' exact binding/dereference idiom rather than introducing a new style.)

## 4) Concrete steps

1. **Re-export the constant.** `linux_command` is currently a *private* module
   (`mod linux_command;`, `crates/rustynet-backend-wireguard/src/lib.rs:6`), so
   `SAFE_BRINGUP_TUNNEL_MTU` (declared `pub const` inside it) is not reachable from outside the
   crate yet. Add it to the crate root's existing re-export list (`lib.rs:17-19`):
   ```rust
   pub use linux_command::{
       LinuxCommandRunner, LinuxWireguardBackend, SAFE_BRINGUP_TUNNEL_MTU, WireguardCommandOutput,
       WireguardCommandRunner,
   };
   ```
   This avoids duplicating the literal `"1420"` as an untracked second copy that could silently
   drift out of sync with the real constant — a real footgun for a privileged-operation gate.
   `rustynetd`'s `Cargo.toml` already depends on `rustynet-backend-wireguard`
   (`crates/rustynetd/Cargo.toml:10`), so no dependency-graph change is needed.

2. **Add the allowlist entry** to `validate_ip_args` in `crates/rustynetd/src/privileged_helper.rs`
   (lines 1865-1931), near the existing `link set up/down` entries. Comment should explain: what
   added this command (FIS-0027 Phase 2), why the value is matched as an exact literal rather than
   any numeric value, and a forward note that Phase 3's dynamic per-path MTU will need this widened
   to a validated bounded range *at that time*, not now.

3. **Add a regression test** in `privileged_helper.rs`'s existing `mod tests` (starts at line
   2215), following the pattern of `validate_request_accepts_macos_endpoint_route_get_schema` (the
   sibling fix for the earlier macOS route-probe allowlist gap — same shape of bug, same shape of
   fix). At minimum:
   - The exact schema `linux_command.rs` sends (`["link", "set", "mtu", "1420", "dev",
     "rustynet0"]`) must be accepted.
   - A different, still-valid u16 MTU (e.g. `"9999"`) must still be **rejected** — this is the test
     that actually proves the literal-match scoping rather than a lazy `parse::<u16>().is_ok()`.
   - A non-interface-name `dev` target must also be rejected.

4. **Verify the caller side is untouched**: `linux_command.rs`'s existing test
   `linux_backend_sets_safe_bringup_mtu_before_link_up` (~line 850) must still pass unchanged — this
   fix only touches the allowlist, never the caller.

## 5) Gates

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --exclude rustynet-mcp --all-targets --all-features -- -D warnings`
  (the exclusion is a known, pre-existing, unrelated toolchain-version lint drift)
- `cargo check --workspace --all-targets --all-features`
- `cargo test -p rustynetd -p rustynet-backend-wireguard`, then the full
  `cargo test --workspace --all-targets --all-features` before merge
- `cargo audit --deny warnings`, `cargo deny check bans licenses sources advisories`

**Live-lab re-verification is the actual proof**, not just unit tests: after the fix lands, re-run
`enforce_baseline_runtime` against a real Linux guest and confirm the daemon's journal no longer
shows `restrict_permanent: reconcile failure threshold exceeded` and `rustynet0` actually appears
(`ip link show rustynet0` on the guest). A green unit-test suite alone does not prove the live
regression is closed — this bug (like the earlier macOS route-probe one) was only ever visible
through live-lab evidence, never through CI.

## 6) Explicit non-goals

- Nothing from the security-audit / A4-attestation / rollback-watermark / branch-consolidation work
  is implicated — do not touch or second-guess any of it here.
- Do not implement FIS-0027 Phase 3 (dynamic per-path MTU) or widen the allowlist beyond the exact
  literal `SAFE_BRINGUP_TUNNEL_MTU` value as part of this fix — that is separate, deliberately
  future-scoped work.
- Do not add a bypass flag or any other weakening of the allowlist's default-deny posture
  (`CLAUDE.md` §3/§10.4) in the course of fixing this.
