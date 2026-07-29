# Cross-Distro Portability Findings (2026-07-29)

**Status:** Active findings record from the second cross-network run, which deliberately
used **different guests and different distros** from the first to test whether the seven
fixes in `CrossNetworkTraversalEvidence_2026-07-29.md` were specific to the four Debian
nodes they were developed on.

**Fleet under test:**

| node | site | distro | arch | NetworkManager | firewalld |
| --- | --- | --- | --- | --- | --- |
| `xnet2-mac-fed` | Mac | Fedora 44 | aarch64 | active | active |
| `xnet2-mac-rocky` | Mac | Rocky 10.2 | aarch64 | active | active |
| `xnet2-ubu-fed` | Ubuntu KVM | Fedora 42 | x86_64 | active | inactive |

**Headline:** the fixes are **not** Debian-specific — Fedora and Rocky on aarch64 both
reached `DataplaneApplied` with the correct 1220 MTU and 2 programmed peers. Getting there
surfaced six issues, one of which turned out to be a latent defect present on every
distro, not a portability quirk at all.

---

## 1. Protected-mode DNS apply cannot write `/etc/resolv.conf` — DEFECT, open

Two layered problems, and the ordering matters. My first reading of this was **wrong**
and is corrected here.

**1a. A symlinked `/etc/resolv.conf` is rejected outright.**

```
dns apply failed: open /etc/resolv.conf for in-place write
(must be an existing regular file): Too many levels of symbolic links
```

That is the **systemd-resolved default** on a stock cloud image
(`/etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf`). Refusing to write through
a symlink is a legitimate posture (symlink-swap attacks); having no handling for the
distro default is the gap.

**1b. Converting it to a regular file does NOT fix it** — the write then fails with
`Read-only file system`, because the unit runs `ProtectSystem=strict` with

```
ReadWritePaths=-/run/rustynet /var/lib/rustynet /etc/rustynet
```

`/etc/resolv.conf` is not in that list, so it is read-only *to the daemon* regardless of
its type or permissions — verified: root can write it fine from a shell. **The unit is
byte-identical on the working Debian node**, so this is not distro-specific at all; it is
latent everywhere and only reached when a DNS apply actually runs.

**Why the other nodes never hit it:** every working node reports `dns_zone_state=absent`
and `dns_alarm_state=missing` — they hold no signed DNS zone, so the apply never executes.

**Causality — corrected.** On the failing node the DNS error is a **secondary** failure
inside the fail-closed rollback, not the primary fault. Counts over three minutes:

| log event | count |
| --- | --- |
| `truncated frame header` | 202 ← **primary** |
| `reconcile_apply_failed` | 200 |
| `rolling back fail-closed` | 80 |
| `dns apply failed` | 94 ← secondary |

So the node fails reconcile first (§5, helper IPC), tries to fail closed, and the
fail-closed path *itself* fails on the DNS write. That second part is the more serious
finding: **a host that needs to enter protected-mode DNS cannot, because the unit does not
grant write access to the file the apply targets.** It is masked today only because no lab
node carries a signed DNS zone.

## 2. Rocky/RHEL sudo `secure_path` omits `/usr/local/bin`

`ops e2e-bootstrap-host` spawns `rustynetd` by **bare name** (`run_status("rustynetd", …)`
in `ops_e2e.rs`), resolved through `PATH`. Under `sudo`:

| distro | `secure_path` |
| --- | --- |
| Rocky 10 | `/sbin:/bin:/usr/sbin:/usr/bin` — **no `/usr/local/bin`** |
| Fedora | includes `/usr/local/bin` |
| Debian | includes `/usr/local/bin` |

So on Rocky the bootstrap dies with
`rustynetd key init failed …: failed to spawn rustynetd: No such file or directory (os error 2)`
even though `/usr/local/bin/rustynetd` exists and runs. This is the same *class* as the
known `/usr/sbin`-not-in-PATH issue.

*Workaround used:* prefix the invocation with an explicit
`env PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin`.
*Proper fix:* spawn the absolute installed path rather than a bare name.

## 3. The CLI enforces its own executable path

Invoking the bootstrap through the build-tree binary fails:

```
[trust-refresh] unexpected executable path:
expected /usr/local/bin/rustynet got <src>/target/release/rustynet-cli
```

Deliberate (the trust-refresh step pins where it may run from), but it means the bootstrap
must be driven via `/usr/local/bin/rustynet` — chicken-and-egg on a host where that has
not been installed yet. Install the CLI first, then bootstrap.

## 4. The privileged helper is a SEPARATE systemd service

Swapping `/usr/local/bin/rustynetd` and restarting only `rustynetd` leaves the **old
helper binary running**, because `rustynetd-privileged-helper.service` is its own unit.
Symptom is an opaque IPC error, not a version complaint. Always restart both:

```
systemctl restart rustynetd-privileged-helper && systemctl restart rustynetd
```

## 5. Helper IPC timeout of 2000 ms is too tight on small guests

On the 2-core Fedora x86 guest the daemon logged
`privileged helper response read failed: truncated frame header` in a loop. Raising
`RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS` from `2000` to `10000` drove those errors to
**zero**. The framing error is what a timeout looks like from the read side, so the
message is misleading — worth surfacing as a timeout rather than a framing fault.

## 6. `/etc/default/rustynetd` freshness windows are not uniform

A freshly bootstrapped host gets production-ish values while hosts carried over from
earlier lab runs keep the lab values:

| node | `TRAVERSAL_MAX_AGE_SECS` | `AUTO_TUNNEL_MAX_AGE_SECS` |
| --- | --- | --- |
| fedora-utm-1, rocky-utm-1 | 86400 | 86400 |
| **fedora-x86-1 (fresh)** | **120** | **3600** |

With 120 s, hand-minted bundles are stale almost immediately and the node fail-closes on
`traversal bundle is stale`. Set both explicitly for lab work; do not assume the file
carries lab values.

## 7. Debian-built binaries run unmodified on Fedora and Rocky

Same binary (md5 identical), glibc 2.39 / 2.41 / 2.43 — all executed. Cross-distro
binary distribution within an architecture is viable for lab work, so a rebuild per
distro is not required.

## 8. The NetworkManager/MTU race did NOT reproduce

All three nodes run NetworkManager, and two also run firewalld, which is the environment
where `enforce_baseline_runtime` previously flapped on the `ip link set mtu` at
`rustynet0` bring-up. With the userspace-shared backend and the MTU now pinned before
link-up (`e3741da2`), both Fedora and Rocky came up clean at 1220 with no flap. Worth
re-testing on the kernel-WireGuard backend before concluding the race is gone.

---

## Result

- `xnet2-mac-fed` (Fedora aarch64) — `DataplaneApplied`, mtu 1220, 2 peers programmed,
  reflexive endpoint `51.186.254.100:37904`
- `xnet2-mac-rocky` (Rocky aarch64) — `DataplaneApplied`, mtu 1220, 2 peers programmed,
  reflexive endpoint `51.186.254.100:46183`
- `xnet2-ubu-fed` (Fedora x86_64) — blocked by §5 (helper IPC), whose fail-closed rollback
  then trips §1

Two of three distros validated end-to-end. The third stayed blocked, and chasing it is
what surfaced §1b — that protected-mode DNS apply can never write its target file under
the shipped unit hardening, on **any** distro. That is the most valuable thing this run
found, and it is latent rather than distro-specific.
