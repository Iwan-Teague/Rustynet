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

## 1. A symlinked `/etc/resolv.conf` defeats the helper's ReadWritePaths — DEFECT (diagnostic), open

**I got this wrong twice before landing on the mechanism. Both earlier readings are
retracted here.**

- ~~"Fedora-specific: symlinked resolv.conf is rejected"~~ — the symlink is involved, but
  the rejection is not the whole story.
- ~~"`ReadWritePaths` omits `/etc/resolv.conf`"~~ — **false.** I was reading the *daemon*
  unit. The write is performed by the **privileged helper**, whose unit does include it:
  `ReadWritePaths=-/run/rustynet -/proc/sys/net/ipv4 -/proc/sys/net/ipv6 -/etc/resolv.conf -/etc/NetworkManager/conf.d`

**Actual mechanism.** systemd resolves `ReadWritePaths` entries **when it builds the
unit's mount namespace**. With `/etc/resolv.conf` a symlink to
`../run/systemd/resolve/stub-resolv.conf` (the systemd-resolved default on a stock cloud
image), the entry binds the *stub target*, which is outside the writable set. The helper's
in-place `O_NOFOLLOW` write then fails — first as
`Too many levels of symbolic links`, and after the file is converted, as
`Read-only file system` **until the helper is restarted**, because the stale namespace
still holds the old bind mount. The `-` prefix means systemd tolerates the situation
silently rather than failing at start, so nothing surfaces the misconfiguration.

**Verified fix on the host** (both steps are required):

```
# 1. replace the symlink with a regular file
cp --remove-destination "$(readlink -f /etc/resolv.conf)" /etc/resolv.conf
# 2. rebuild the helper's mount namespace -- restarting only the daemon is NOT enough
systemctl restart rustynetd-privileged-helper && systemctl restart rustynetd
```

Applied to `xnet2-ubu-fed`, it went from no interface to **`mtu 1220`, STUN discovering
`213.233.155.131:14337`, zero errors** — third distro unblocked.

**Why Linux cannot self-heal this.** macOS already handles a symlinked resolv.conf with an
atomic temp+`rename` (which swaps the symlink for a regular file), but that needs a
writable `/etc`. On Linux `ProtectSystem=strict` deliberately keeps `/etc` read-only apart
from the single resolv.conf inode, so the helper **cannot** rename in `/etc` — by design.

**So the product gap is diagnostic, not mechanical:** the operator gets
`Too many levels of symbolic links` or `Read-only file system` from deep inside a
fail-closed rollback, with no indication that the cause is a symlinked resolv.conf or that
the remedy involves restarting the *helper*. A preflight check that names the condition and
the fix is the right change.

**Causality on the failing node.** The DNS error was **secondary**. Counts over three
minutes: `truncated frame header` 202 (primary, §5 helper IPC) → `reconcile_apply_failed`
200 → `rolling back fail-closed` 80 → `dns apply failed` 94. Diagnose the helper IPC
first; do not start at resolv.conf.

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
link-up (`d1a8f0df`), both Fedora and Rocky came up clean at 1220 with no flap. Worth
re-testing on the kernel-WireGuard backend before concluding the race is gone.

---

## Result

- `xnet2-mac-fed` (Fedora aarch64) — `DataplaneApplied`, mtu 1220, 2 peers programmed,
  reflexive endpoint `51.186.254.100:37904`
- `xnet2-mac-rocky` (Rocky aarch64) — `DataplaneApplied`, mtu 1220, 2 peers programmed,
  reflexive endpoint `51.186.254.100:46183`
- `xnet2-ubu-fed` (Fedora x86_64) — **unblocked**, `DataplaneApplied`, mtu 1220,
  reflexive endpoint `213.233.155.131:14337`

**All three distros validated.** The traversal fixes are not Debian-specific. The most
valuable find was §1: a symlinked `/etc/resolv.conf` silently defeats the helper's
`ReadWritePaths`, and recovering from it needs a **helper** restart, not just a daemon
restart — surfaced only as an opaque EROFS from inside a fail-closed rollback.
