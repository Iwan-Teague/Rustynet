# Windows `collect_pubkeys` empty-read of `wireguard.pub` — grounded code-trace analysis

**Status:** analysis complete; no code changed (docs-only deliverable).
**Date:** 2026-09-04 (written 2026-09-05 in worktree `ai-edit/edit-1788563825461-26537-27`, base commit `9aabe6b3`).
**Scope:** trace every path that writes, truncates, deletes, renames, or replaces `C:\ProgramData\RustyNet\keys\wireguard.pub` (`DEFAULT_WINDOWS_WG_PUBLIC_KEY_PATH`, `crates/rustynetd/src/windows_paths.rs:70`), classify each as atomic vs. window-bearing, and place each on the fresh-`--node`-bootstrap timeline relative to the readiness probe and `collect_wireguard_public_key`.

> ## UNTRUSTED
> This document was produced by a delegated AI edit agent from a static code trace of the
> repository at the commit named above. It has NOT been independently verified by a human,
> and it is NOT live-lab evidence: no run was launched, no guest was inspected, and the
> run-2026-09-04-windows-7 observations it references are taken from in-repo comments, not
> from the run's artifacts. Line numbers are from this worktree's checkout of `9aabe6b3`
> and will drift as the touched files evolve. Treat every conclusion as a hypothesis to
> confirm against the live lab before acting on it.

## 1. The symptom

During a fresh `--node` Windows bootstrap, `collect_wireguard_public_key`
(`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs:48`) read
`wireguard.pub` via `Get-Content -LiteralPath … -Encoding utf8 -Raw` and got an empty
string, although the bootstrap readiness probe had confirmed the file present AND
non-empty moments earlier. Per the in-repo comment at `windows_traffic.rs:64-67`
(referencing run-2026-09-04-windows-7), the key was a valid 45-char base64 value on the
guest immediately afterwards — i.e. the empty read was transient, and the file is stable
under steady state (24/24 samples len=45, from the operator's manual restart experiment).

## 2. Writer inventory — every path that touches `wireguard.pub`

### 2.1 Writers (all atomic)

Every writer that can create or replace the public-key file funnels through
`write_public_key` (`crates/rustynetd/src/key_material.rs:1011`), which:

- rejects a trim-empty value ("public key must not be empty") — `key_material.rs:1011-1017`;
- formats the key with a trailing newline and delegates to `write_atomic` with mode
  `0o640` — `key_material.rs:1011-1032`;
- `write_atomic` (`key_material.rs:1342-1458`) builds a unique temp file in the same
  directory (suffix `.tmp.<pid>.<nanos>`, `key_material.rs:1460-1468`), creates it with
  `create_new` (`:1418-1424`), writes, `sync_all` (`:1432`), then
  `fs::rename(temp, path)` (`:1439`). On Windows `std::fs::rename` maps to
  `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, i.e. an atomic name swap: a concurrent
  reader observes either the old content or the new content, never a truncated or absent
  file. (Failure path: the temp file is removed on write error, `:1425`.)

Call sites of `write_public_key`, all atomic by construction:

| Call site | When it runs | Runs on fresh Windows first-start timeline? |
| --- | --- | --- |
| `initialize_encrypted_key_material`, `key_material.rs:1240-1245` (via `rustynetd key init`, `crates/rustynetd/src/main.rs:2927-2990`, invoked by the install script at `windows_install.rs:1063` with `--force`) | install-time key init, BEFORE service start | Yes — but before the service exists, hence before readiness |
| `DaemonRotationIo` prepare-swap, `crates/rustynetd/src/daemon.rs:11312-11316` | key rotation commit | **No — unreachable on Windows:** `rotate_local_key_material` hard-guards on `LinuxWireguard | MacosWireguard` and returns `Err` otherwise (`daemon.rs:10071-10079`) |
| `restore_key_backups`, `daemon.rs:10188-10192` | rotation rollback only | No — same rotation guard applies |

Note on the `--force` path: `initialize_encrypted_key_material` refuses to overwrite
existing material unless `--force` (`key_material.rs:1221-1230`); with `--force` it
regenerates a keypair and writes via the same atomic helpers. Its only
`remove_file_if_present` calls on the public path are the write-failure cleanup at
`key_material.rs:1244-1245` (and the mirror site in
`migrate_existing_private_key_material` at `:1330-1331`) — both fire only when
`write_public_key` itself returned `Err`, at which point the write never happened.

### 2.2 Removers (do not run on the fresh-first-start timeline)

| Remover | Trigger | Reachable pre-membership on Windows? |
| --- | --- | --- |
| `remove_file_if_present` on the public path inside `revoke_local_key_material`, `daemon.rs:10232-10237` | explicit IPC key-revoke command | No — requires an explicit operator/IPC action |
| `scrub_runtime_private_key_file`, `daemon.rs:10260-10267` | post-rotation cleanup | Private-key file only; never the public key; rotation-guarded anyway |
| `scrub_runtime_wireguard_key_material`, `daemon.rs:10270-10278` | scrub path | Takes only the private + encrypted-private paths; the public key is not an input |

`remove_file_if_present` itself (`key_material.rs:1170-1188`) scrubs the file contents to
zero before unlinking (`scrub_file_contents`, `:1190-1212`), so between scrub and unlink
a reader could see an EMPTY file — a genuine window — but no automatic path applies this
to `wireguard.pub` on the Windows first-start timeline (see table above).

One remove-then-rename window DOES exist in `key_material.rs` — the Windows DPAPI
passphrase-blob writer at `:315-386` calls `remove_file_if_present(path)` at `:363`
followed by `fs::rename` at `:365` — but that file is the **key passphrase blob**, not
`wireguard.pub`, so it cannot explain the observed empty pubkey read. It is noted here
for completeness because it is the only genuine remove-then-rename absence window found
in the key-material module.

### 2.3 Non-writers at daemon startup

`run_daemon`'s key-material prep does **not** rewrite the public key:

- `prepare_runtime_wireguard_key_material` (`daemon.rs:12964-13007`) either decrypts the
  encrypted private key in memory (Windows WireGuard-NT in-memory custody:
  `daemon.rs:12988-12996` zeroes the plaintext and returns without writing anything) or
  validates the plaintext runtime key (`:13006`). It takes no public-key path and never
  writes one.
- The startup "self-heal" calls `tighten_public_key_permissions`
  (`daemon.rs:12950-12961`), which on non-Unix platforms is a no-op
  (`key_material.rs:1066-1068`) — a chmod at most on Unix, never a rewrite.
- Config preflight (`daemon.rs:13389-13392`, `:13939-13942`) only validates paths and
  permissions — read-only.

**Paths checked and NOT found:** any daemon-startup re-derivation or rewrite of
`wireguard.pub`; any non-atomic (truncate-then-write / remove-then-write) writer of
`wireguard.pub` anywhere in `crates/rustynetd`; any orchestrator-side Windows bootstrap
code that writes `wireguard.pub` (the orchestrator only READS it —
`crates/rustynet-cli/src/vm_lab/mod.rs:22590-22595`, whose comment states "The key file
is written by the daemon at startup"; on macOS the bootstrap script does write the file
itself, `mod.rs:11355-11363`, but that is the macOS path, not Windows).

## 3. The two stale comments

Two in-repo comments assert a mechanism the code does not support:

1. `windows_traffic.rs:62-63`: "The daemon writes wireguard.pub non-atomically (truncate
   then write) as it (re)derives the key at startup/reconcile" — §2 shows every
   `wireguard.pub` writer is atomic temp+rename, and nothing rewrites the file at startup
   or reconcile on Windows.
2. `windows_install.rs:881-883`: "the daemon creates the file and writes the key
   asynchronously at startup" — no such startup writer exists (§2.3). The file is created
   by `rustynetd key init` during install (`windows_install.rs:1063`), before the service
   starts.

These comments likely describe an older build or were inferred from the symptom rather
than the code. They should be corrected when the code next changes (proposed, not
implemented here — docs-only task).

## 4. Timeline of the fresh Windows bootstrap

1. Install script runs `rustynetd key init --passphrase-file … --force`
   (`windows_install.rs:1063`) → atomic write of `wireguard.pub` (§2.1). From this point
   the file exists with valid content.
2. Membership init + service start (`windows_install.rs:979` comment block).
3. Readiness fragment `windows_daemon_status_readiness_fragment`
   (`windows_install.rs:885-913`): polls up to 30×2s for SCM Running AND env-file present
   AND `wireguard.pub` present AND non-whitespace (`:893-901`). A transient read failure
   here just extends the wait; it cannot produce a false-ready.
4. `collect_wireguard_public_key` (`windows_traffic.rs:48-83`) reads the same path.
   Since commit `0d0a1a69` it retries up to 8 times with 1s sleeps, failing closed only
   when every attempt comes back empty/undecodable (`windows_traffic.rs:68-81`).

Between (3) and (4) the traced code performs **no** write, remove, rename, or truncate of
`wireguard.pub`: rotation is platform-guarded away (§2.1), revoke needs an explicit
command (§2.2), startup prep never touches the public path (§2.3), and no reconcile hook
rewrites it. The daemon's early reconciles failing closed on membership-missing /
trust-sig-failed (per the operator's daemon logs) do not enter `rotate_local_key_material`
— and could not on Windows even if invoked, because of the backend guard.

## 5. Conclusion — most likely mechanism

The static trace **rules out** a daemon-side content race as the mechanism: there is no
code path on the fresh Windows first-start timeline that truncates, empties, removes, or
non-atomically replaces `wireguard.pub` between the readiness probe and the collector.
Both in-code explanations for the symptom (§3) are stale.

The remaining plausible explanations, in order of likelihood:

1. **Transient read-side failure, not content churn.** `Get-Content -Raw` on Windows
   emits nothing (empty stdout) when the open fails — e.g. a sharing violation while
   another process holds the freshly written key file (Defender/AV first-scan of a new
   file in `C:\ProgramData` is the classic cause) or while a rename over the file is in
   flight. The collector then decodes an empty string ("empty base64 input"). This is
   consistent with the observation that the file was intact immediately afterwards. This
   cannot be proven from the repo alone; confirming it requires guest-side evidence
   (e.g. reading the file with `fsutil`/handle tracing during a repro).
2. **Out-of-tree actor on the guest** (old daemon build from a prior install lingering on
   the host, or an external cleanup script) briefly removing/rewriting the file. Nothing
   in the current tree does this; the manual steady-state stability experiment (24/24
   non-empty) argues against recurring churn.
3. **A stale pre-`0d0a1a69` observation.** The readiness probe originally checked
   presence only, and the collector had no retry; the doc comment at
   `windows_install.rs:878-884` records exactly that failure mode and the fix (require
   non-empty). If run-2026-09-04-windows-7 predated that hardening, the "empty after
   ready" reading may simply be the old presence-only race. Verify which hardening the
   run's deployed source actually carried before treating the symptom as still live.

## 6. Proposed fix (NOT implemented — this task is docs-only)

Preferred, in order:

1. **Read the public key from a stable, daemon-served source instead of churning the
   file.** The §4.7 live-identity challenge already exists precisely because on-disk
   artifacts are not proof of live identity (`crates/rustynet-cli/src/vm_lab/orchestrator/
   role_validation/identity_challenge.rs:18`, and `collect_node_id`'s doc at
   `windows_traffic.rs:97-99` pointing at `query_live_identity`). Extend the daemon
   status/live-identity response (or a read-only IPC surface) to include the active
   WireGuard public key, and have `collect_wireguard_public_key` prefer that response.
   This removes both the file-read failure mode and any dependence on file timing.
2. **Keep the existing mitigations** (they are already landed in `0d0a1a69`): the
   readiness probe's non-empty requirement (`windows_install.rs:893-901`) and the
   collector's bounded retry (`windows_traffic.rs:68-81`). They are cheap and defense in
   depth even after (1).
3. **Correct the two stale comments** (`windows_traffic.rs:62-63`,
   `windows_install.rs:881-883`) to describe the actual writer inventory — atomic
   `write_public_key`/`write_atomic`, install-time creation, no startup rewrite — so the
   next investigator does not re-derive the refuted mechanism.
4. If guest-side evidence later shows an AV-lock cause, consider a retry-with-backoff
   tweak (exponential rather than fixed 1s) rather than any writer change — no writer
   change is warranted by the current evidence.

## 7. Evidence index

- `windows_paths.rs:70` — `DEFAULT_WINDOWS_WG_PUBLIC_KEY_PATH`.
- `key_material.rs:1011-1032` — `write_public_key` (empty-reject, atomic).
- `key_material.rs:1342-1468` — `write_atomic` (temp + `fs::rename` :1439).
- `key_material.rs:1170-1212` — `remove_file_if_present` + `scrub_file_contents`.
- `key_material.rs:1214-1252` — `initialize_encrypted_key_material` (force gate
  :1221-1230; failure-only removes :1241/:1245).
- `key_material.rs:1254-1338` — `migrate_existing_private_key_material` (failure-only
  removes :1327/:1331).
- `key_material.rs:315-386` — DPAPI passphrase-blob writer (the only remove-then-rename
  window, `:363`/`:365`; passphrase file, not the pubkey).
- `key_material.rs:1034-1068` — `tighten_public_key_permissions` (no-op on non-Unix
  :1066-1068).
- `daemon.rs:10071-10079` — rotation backend guard (Linux/macOS only).
- `daemon.rs:10188-10192` — `restore_key_backups` pub restore (rotation path).
- `daemon.rs:10203-10237` — `revoke_local_key_material` (explicit-only removes,
  pub at :10232-10237).
- `daemon.rs:10260-10267` — `scrub_runtime_private_key_file` (private only).
- `daemon.rs:12964-13007` — `prepare_runtime_wireguard_key_material` (no pub write;
  Windows in-memory decrypt path :12988-12996).
- `daemon.rs:12950-12961` — startup `tighten_public_key_permissions` self-heal.
- `daemon.rs:11312-11316` — rotation prepare-swap pub write (rotation-guarded).
- `main.rs:2927-2990` — `run_key_init` → `initialize_encrypted_key_material`.
- `windows_install.rs:878-913` — readiness fragment (non-empty requirement :893-901;
  stale "asynchronously at startup" comment :881-883).
- `windows_install.rs:1063` — install invokes `rustynetd key init … --force`.
- `windows_install.rs:979` — stage order comment (key init → membership init → service
  start).
- `windows_traffic.rs:48-83` — `collect_wireguard_public_key` (8×1s retry :68-81;
  stale "non-atomically (truncate then write)" comment :62-63).
- `windows_traffic.rs:97-99` — `collect_node_id` doc: live identity must come from the
  daemon status response, not files.
- `mod.rs:22590-22595` — orchestrator-side Windows pubkey read (read-only; "written by
  the daemon at startup").
- `mod.rs:11355-11363` — macOS bootstrap script writes the pub file (macOS only, listed
  to mark the contrast; not the Windows path).
- `identity_challenge.rs:18` — files are not proof of live identity (§4.7 motivation).
- Commit `0d0a1a69` — "fix(vm-lab/windows): retry the pubkey read + use sc.exe stop in
  cleanup (live-corrected)" — landed the readiness non-empty requirement and the
  collector retry.
