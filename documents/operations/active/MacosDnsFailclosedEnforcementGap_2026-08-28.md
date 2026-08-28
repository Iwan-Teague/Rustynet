# macOS DNS fail-closed enforcement gap — findings + owner-gated fix design — 2026-08-28

**Status: DESIGN-ONLY, owner-gated. No code changed.** The QH-39 `scutil --dns`
observation landed and is correct; what it exposed is that macOS DNS
fail-closed **enforcement** does not exist for the resolver configuration macOS
actually uses. This document records the evidence, the exact enforcement
mechanisms available, the trade the owner must adjudicate, and the fix shape.
Until an owner-approved enforcement lands, the macOS DnsFailclosed check is
expected to **red on every protected macOS node** — that red is honest (the
posture is not enforced), not a validator defect.

## 1. The finding

Run `livelab-1787911937-77ff1933885f` (MAC-CELLS run 3 / ledger row 47,
`macos-utm-1:anchor` + Linux backbone, clean `77ff1933`) failed
`validate_baseline_runtime` on `macos-utm-1/DnsFailclosed` alone — the other
five probes passed. Guest observation (MacCellsHarvest_2026-08-28.md §3.1):

```
$ cat /etc/resolv.conf
# rustynet protected-mode DNS fail-closed
nameserver 127.0.0.1

$ /usr/sbin/scutil --dns        # resolver #1 (the primary)
  nameserver[0] : 1.1.1.1
  nameserver[1] : 8.8.8.8
```

`macos-dns-failclosed-check` exits `policy_reject (78)` with drift reason
`"macOS loopback resolver is not advertised by /usr/sbin/scutil --dns
(primary resolver is off-loopback, empty, or unreadable); DNS fail-closed
posture cannot be verified"`.

**Verdict: the check is correct; the finding underneath is real.** On macOS the
system resolver is mDNSResponder driven by SystemConfiguration; `/etc/resolv.conf`
is a configd-generated compatibility shim that the primary lookup path ignores
(the file itself declares it "not consulted for DNS hostname resolution … by
most processes on this system"). RustyNet's protected-mode apply writes that
shim and nothing else, so the resolver configuration the OS actually uses was
never locked to loopback. **DNS resolving to a non-loopback server on a
protected node is a leak** — here contained only incidentally by the pf egress
`:53` block (§2), with the advertised posture contradicting it.

## 2. What the macOS apply path sets today (code facts)

`MacosCommandSystem::apply_dns_protection` (`crates/rustynetd/src/phase10.rs:4081-4130`)
does three things, in order:

1. **pf DNS rules** (`apply_pf_rules`) — tunnel-interface DNS pass + egress
   `block … proto udp/tcp … port 53`. This is REAL containment: off-host
   `:53` egress is dropped. It is the self-described "primary fail-closed
   enforcement" and is asserted by `assert_dns_protection` (`:4132-4153`) —
   which asserts **only** the pf rules and never the resolver state.
2. **`resolv-conf-apply`** (privileged-helper `dns-failclosed-file` builtin,
   best-effort) — rewrites `/etc/resolv.conf` to the loopback resolver.
   **Cosmetic on macOS**: mDNSResponder does not consult the file for the
   default lookup path. The in-code comment at `:4094-4100` already concedes
   the write is best-effort because macOS manages the file via
   system-configuration and may revert it.
3. **`macos-resolver-apply`** (best-effort) — writes `/etc/resolver/rustynet`,
   a **per-domain scoped** resolver routing only `*.rustynet` to the daemon's
   loopback `:53535` bind. Necessary for mesh names; touches nothing else.

Rollback (`rollback_dns_protection`, `:4155-4172`) reverses 2 and 3 and
re-renders pf. Nothing in apply, assert, or rollback touches SystemConfiguration.

The Linux twin enforces because on Linux `/etc/resolv.conf` **is** the resolver
source (`linux_dns_protect.rs`): loopback resolv.conf + NM `dns=none` drop-in +
nft `:53`→resolver redirect, all asserted. macOS has **no SystemConfiguration
equivalent of any of the three**. That asymmetry is the gap.

A note on what actually happens to a non-mesh lookup on a protected macOS node
today: mDNSResponder tries the configured servers (1.1.1.1, 8.8.8.8), pf drops
the egress, the query times out. Resolution is dead (fail-closed in effect) but
the node **advertises** off-box resolvers — and any hole in the pf anchor
(anchor unload, rule drift, another security layer's exception) turns the
advertised configuration into real leakage instantly. The enforced-posture and
the advertised-posture must be the same thing; today they are not.

## 3. Why `/etc/resolver/` cannot close it

`/etc/resolver/<name>` files are **per-domain scoped** resolvers. There is no
supported file-based mechanism that sets the DEFAULT resolver for
non-mesh domains: a scoped file requires a `domain` directive, and no
"default route" file exists. Loopback-only default resolution therefore
requires SystemConfiguration state. (Verified against Apple's resolver
semantics as documented in `resolver(5)`; the repo's own module docs at
`linux_dns_protect.rs:172-198` record the same scope limitation.)

## 4. Candidate mechanisms

### M1 — `networksetup -setdnsservers` per service (persistent, documented)

- New privileged program `NetworkSetup` → fixed `/usr/sbin/networksetup`
  (argv-only, same pattern as `Pfctl`/`Sysctl` fixed-path candidates in
  `privileged_helper.rs`).
- Enumerate: `-listallnetworkservices` (read; helper `run_capture`, precedent
  `pfctl -s rules`). Parse the plain-text list (skip the header and trailing
  legend; `*` prefix marks a disabled service).
- Apply: one `-setdnsservers <service> 127.0.0.1` per service.
- Restore: capture per-service originals with `-getdnsservers <service>`
  (`"There aren't any DNS Servers set on …"` = none) at apply time into the
  helper runtime dir (same session-scoped backup pattern as
  `RESOLV_CONF_FAILCLOSED_BACKUP_PATH`); restore exact lists, or `Empty` where
  none were set.

Pros: the documented Apple interface; configd pushes the change into
mDNSResponder immediately; `scutil --dns` primary becomes loopback (the QH-39
check passes); configd then **regenerates** `/etc/resolv.conf` from SC state —
the cosmetic write of §2 step 2 becomes self-consistent and self-healing.

Cons: the setting **persists** in `/Library/Preferences/SystemConfiguration`
across reboot. A crash-without-teardown leaves the host's DNS pointed at a
loopback port nothing listens on — **no self-heal**, indefinitely, until a
manual `networksetup -setdnsservers <svc> Empty`. The pf rules self-heal
(daemon re-asserts) and resolv.conf self-heals (configd); this would be the one
protection that strands. Also a per-service **policy** choice (all hardware
services? exclude VPN/bridge services?), and service names are free-form
strings crossing the privileged argv boundary — a new validation surface
(control-char/newline rejection minimum).

### M2 — `scutil` State:/ dynamic-store override (volatile, undocumented)

- Keep the argv-only seam: a new fixed-content selector on the existing
  `dns-failclosed-file` builtin writes a fixed scutil script to the helper
  runtime dir (e.g. `/private/var/run/rustynet/scutil-dns-failclosed.scutil`),
  then exec `/usr/sbin/scutil -f <fixed-path>` (no stdin, no shell).
- Script shape: per service ID (enumerated from `show Setup:/Network/Service`
  / `list`), `d.init` + `d.add ServerAddresses * array 127.0.0.1` +
  `set State:/Network/Service/<id>/DNS`.

Pros: State:/ overrides are **volatile** — they vanish on reboot and are
reclaimed by configd on link events, matching the helper/daemon session
lifetime. No persistent strand risk; teardown is a `remove` of the same keys.

Cons: State:/ keys are undocumented/unsupported; configd may rewrite them on
any network event, so — like pf — they must be **re-asserted on the reconcile
loop** rather than applied once; the service-ID enumeration and exact key
layout are design decisions; `scutil` script grammar is versioned only by macOS
release. Weaker guarantee than M1 precisely where M1 is strong.

### M3 — loopback listener on :53 (Linux parity) — REJECTED

The daemon runs unprivileged on macOS (`UserName=rustynetd`; no capability or
ambient-certificate mechanism exists), so it cannot bind `:53`; macOS installs
no `:53`→`:53535` redirect (a pf `rdr` on `lo0` is unreliable across macOS
versions). Documented in `linux_dns_protect.rs:181-188`. Rejected without an
owner exception to run a privileged helper listener.

## 5. The decisions the owner must make (gates on implementation)

1. **M1 vs M2** — persistent-documented with a strand risk, vs
   volatile-undocumented with a re-assertion requirement. The
   strictest-secure-practical reading favors **M1 + reconcile re-assertion**
   (documented interface, self-consistent resolv.conf, and the strand risk
   bounded by the same crash-recovery path QH-40 built for pf: a startup
   check that finds fail-closed DNS state with no running protection RESTORES
   before refusing), but the strand-on-crash consequence is a real
   availability trade that needs sign-off either way.
2. **Service scope policy** — all `listallnetworkservices` entries vs hardware
   services only; treatment of disabled (`*`) services; treatment of VPN
   services that install their own resolvers.
3. **New privileged argv surface** — service names/IDs are host-derived but
   caller-composed argv to a root exec; needs a validation rule (reject
   control characters, empty, overlong) plus negative tests, mirroring
   `is_owned_nft_table_token`.
4. **Posture confirmation** — with SC primary = `127.0.0.1` and nothing
   listening on `:53`, ALL non-mesh lookups fail fast locally instead of
   pf-timing-out. That is today's behavior made honest, but it should be
   confirmed as the intended macOS posture — including its interaction with
   the RustyDNS tandem decree
   (`RustydnsExitIntegrationDecree_2026-08-25.md`): if RustyDNS later owns
   forwarding, it — not an empty loopback port — must be the `:53` listener,
   and the ownership handoff order must be explicit (RustyDNS listening
   BEFORE the SC switch, revoked AFTER).
5. **Ordering** — DNS enforcement is part of protected-mode entry/exit; per
   AGENTS §10.7 the teardown ordering rule applies: restore SC DNS BEFORE
   removing the pf anchor (otherwise a window exists where resolution is
   advertised-loopback-but-unfiltered).

## 6. Verification plan (once implemented)

- **The QH-39 check becomes the verifier.** Enforced state must make
  `sudo rustynetd macos-dns-failclosed-check` exit 0 on the guest
  (`overall_ok: true`, primary resolver loopback); reverting the enforcement
  must red it. That is the live negative case, and it is already shipped.
- `assert_dns_protection` gains a SystemConfiguration assertion alongside the
  pf assertion: query the applied state (M1: `networksetup -getdnsservers`
  per service; M2: `scutil --dns` parse via
  `parse_scutil_primary_resolver_nameservers`) and fail
  `SystemError::DnsApplyFailed` on drift — making the protected-mode entry
  fail closed when the resolver state cannot be set/verified.
- Unit tests: pure argv builders (enumerate/apply/restore), the service-list
  parser (header/legend/`*`/blank handling), name validation negatives
  (control chars, empty), backup-capture/restore round-trip, and the
  assert-path drift detection. All testable on this macOS host.
- Live: a macOS anchor-cell `validate_baseline_runtime` with `DnsFailclosed`
  green, ledger row + stage artifact as evidence.

## 7. Disposition

- **2026-08-28 — design-only, owner-gated; no code changed.** Investigated
  and documented from run `livelab-1787911937-77ff1933885f` +
  `MacCellsHarvest_2026-08-28.md` §3.1. The enforcement mechanism is a
  security-boundary change (new privileged program, service-scope policy,
  persistence semantics) — per the repo's decision protocol it is specified
  here and gated on owner sign-off rather than guessed at. QH-39's ledger
  entry carries the same disposition.

- **2026-08-28 — DONE: M1 implemented (owner-approved).** New privileged program
  `NetworkSetup` — fixed path `/usr/sbin/networksetup`, argv-only, per-program allowlist
  `validate_networksetup_args` in `privileged_helper.rs` (`-listallnetworkservices`,
  `-getdnsservers <svc>`, `-setdnsservers <svc> 127.0.0.1|Empty|<exact saved IP list>`).
  Service names cross the privileged argv boundary, so they are validated there
  (`is_valid_networksetup_service_name`: non-empty, ≤128 bytes, no control characters),
  mirroring `is_owned_nft_table_token`, with negative tests. Enforcement module:
  `crates/rustynetd/src/macos_dns_sc_protect.rs` (service-list/getdns parsers, argv
  builders, session-scoped backup at
  `/private/var/run/rustynet/networksetup-dns.failclosed.bak`, startup-guard decision
  function). Scope per §5 item 2: ALL ENABLED hardware network services (the
  `*`-prefixed disabled services and the header/legend are skipped).
  `MacosCommandSystem::apply_dns_protection` now enumerates the services, captures each
  service's current DNS into the backup BEFORE the first mutation, and pins every
  service to `127.0.0.1`; any enumeration, backup, or set failure fails the apply
  (`SystemError::DnsApplyFailed`) with the pf DNS-block rules left installed
  (`dns_protected` intentionally stays true so the reconcile re-render cannot drop
  them — entry still fails closed). `assert_dns_protection` gained the
  SystemConfiguration assertion: per-service `-getdnsservers` must show loopback-only;
  drift fails the assert, driving the reconcile loop to re-assert.
  `rollback_dns_protection` restores each backed-up service DNS exactly (or `Empty`
  where none was set) BEFORE the pf anchor reload (§10.7 ordering — no
  advertised-loopback-but-unfiltered window); a failed restore returns WITHOUT dropping
  the anchor and retains the backup for retry. The approved startup-recovery guard
  (daemon.rs, before any protection is applied in-process, QH-40-shaped) restores the
  backup when SC DNS is loopback with no protection running; with no readable backup it
  refuses to start, loudly, naming the manual fix per service
   (`sudo /usr/sbin/networksetup -setdnsservers "<svc>" Empty`). Verification: the
  shipped QH-39 `macos-dns-failclosed-check` — with enforcement applied the SC primary
  resolver is loopback so the check passes; reverting the pin reds it. Unit coverage:
  13 module tests (parsers incl. header/legend/`*`/blank handling, validators with
  control-char/empty/overlong negatives, argv builders, backup round-trip and
  corrupt/foreign-schema/empty refusals, startup-guard truth table) plus the helper
  validator allowlist test. **Residual owner sub-decision (§5 item 2, still open):**
  VPN/utun services that manage their own resolver are NOT special-cased — the loopback
  pin applies to all enabled services. If that proves harmful in practice the owner can
  exclude named services via config later.

- **2026-08-28 — HARDENED: backup-baseline loopback-residue edge closed** (security
  review follow-up to the M1 item above). The capture path could previously record a
  service's CURRENT DNS as the backup baseline even when that value was ALREADY the
  loopback posture M1 enforces — residue from a prior apply whose teardown never ran
  (reachable when the startup-recovery guard was bypassed because scutil was unreadable:
  `read_scutil_dns` → `None` ⇒ `NoAction`). A loopback baseline would have made any
  later rollback "restore" the strand instead of the operator's real DNS. The capture
  site (`MacosCommandSystem::apply_dns_protection` in `phase10.rs`) now reads the prior
  backup document before building the baseline and resolves each service through the new
  pure helper `resolve_backup_baseline_entry` (`macos_dns_sc_protect.rs`): a normal
  (non-loopback) capture — including the no-servers case — is recorded unchanged;
  loopback residue with a readable prior backup PRESERVES that document's entry for the
  service (the real pre-enforcement original) instead of overwriting it with loopback;
  loopback residue with NO prior entry for the service refuses the apply loudly
  (`SystemError::DnsApplyFailed`) naming the manual fix (`sudo
  /usr/sbin/networksetup -setdnsservers "<svc>" Empty`, or the operator's real DNS). A
  prior backup that is PRESENT but unreadable also fails the apply before any baseline
  is built (an unverifiable document cannot vouch for an original). Loopback is never
  silently recorded as a baseline. Unit coverage: 3 new module tests
  (`backup_baseline_refuses_loopback_residue_without_prior_original`,
  `backup_baseline_preserves_prior_original_over_loopback_residue`,
  `backup_baseline_records_normal_captured_dns_unchanged`).
