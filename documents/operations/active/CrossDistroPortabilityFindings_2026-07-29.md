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
reached `DataplaneApplied` with the correct 1220 MTU and 2 programmed peers. Getting
there surfaced six distinct portability issues, one of which is a genuine product defect.

---

## 1. Symlinked `/etc/resolv.conf` breaks DNS apply — PRODUCT DEFECT, open

```
dns apply failed: i/o failed: open /etc/resolv.conf for in-place write
(must be an existing regular file): Too many levels of symbolic links
```

The DNS apply refuses to write through a symlink. That refusal is a *legitimate* security
posture (symlink-swap attacks), but there is no handling for the case that is the
**systemd-resolved default**, where `/etc/resolv.conf` is a symlink to
`../run/systemd/resolve/stub-resolv.conf`. On such a host the failure cascades:
DNS apply fails → fail-closed rollback → **the WireGuard backend never starts** →
no `rustynet0`, no traversal, node stuck `FailClosed`.

Measured across the fleet — every node runs systemd-resolved, so the discriminator is
purely the symlink:

| node | `/etc/resolv.conf` | outcome |
| --- | --- | --- |
| fedora-utm-1, rocky-utm-1, debian-x86 | regular file | works |
| **fedora-x86-1** | symlink → stub-resolv.conf | **backend never starts** |

The three "working" nodes had been converted to a regular file by earlier lab runs; a
**stock cloud image keeps the symlink**, so this hits any fresh systemd-resolved host.

*Not yet fixed.* The right fix is to handle the systemd-resolved case deliberately —
either resolve/replace the symlink under a documented, audited path, or integrate with
resolved — rather than to relax the regular-file check.

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
- `xnet2-ubu-fed` (Fedora x86_64) — blocked by finding §1

Two of three distros validated end-to-end; the third is blocked by a product defect that
would hit any stock systemd-resolved host, which is the most valuable thing this run found.
