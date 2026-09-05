# Windows `--node` bootstrap after `collect_pubkeys` — code-trace analysis (membership_init → distribute_* → enforce_baseline_runtime)

- Status: analysis (docs-only; no code changed by this document)
- Date: 2026-09-05
- Scope: static code trace of the Windows bootstrap path for guest `windows-x86-1` AFTER `collect_pubkeys`: `membership_init`, `distribute_membership`, `anchor_validation`, `admin_issue`, `distribute_assignments`, `distribute_traversal`, `distribute_dns_zone`, `enforce_baseline_runtime`. Companion to `WindowsCollectPubkeysEmptyReadAnalysis_2026-09-04.md` (the `collect_pubkeys` empty-read defect, fixed on main in commit `70e16a63`).

> ## UNTRUSTED
>
> This document was produced by a delegated AI edit agent as a **static code trace**, not from a live-lab run. It contains no live-lab evidence: every claim below is a reading of the source at the commit this worktree branched from. Line numbers refer to that tree and **will drift** as code changes. Treat every conclusion as a hypothesis to verify against the real code and a real run before acting on it.

## 1) Symptom / question

`collect_pubkeys` was fixed (`70e16a63`): the Windows collector now reads the WireGuard public key from the `rustynet.exe status` response instead of a racy read of a key file. The question this document answers: **for the stages that run after `collect_pubkeys` on a fresh Windows guest, what does each stage actually do, what preconditions can be violated, and which file-based reads carry the same write-by-one-moment / read-by-another risk pattern that bit `collect_pubkeys`?** Also: what is the ranked best-guess order of first failures in the next live run.

## 2) Stage order under analysis (real stage IDs, from code)

From `define_stage_catalog` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:174-214`) and the order assertion in `plan.rs:996-1003`:

`collect_pubkeys` → `membership_init` → `distribute_membership` → `anchor_validation` (T1Role) → `admin_issue` (T1Role) → `distribute_assignments` → `distribute_traversal` → `distribute_dns_zone` → `enforce_baseline_runtime` → `blind_exit` → `validate_baseline_runtime` → live stages.

**There is no `distribute_dataplane` stage.** The dataplane-relevant stages are `distribute_assignments`, `distribute_traversal`, `distribute_dns_zone`, all sharing one implementation (`distribute_bundle_kind`).

All stages in this window are Setup-tier (`membership_init` / `distribute_*` @ T0Core; `anchor_validation` / `admin_issue` @ T1Role, `stage/mod.rs:186-193`).

## 3) `membership_init` on Windows

### 3.1 Orchestrator side

`MembershipInitStage` (`orchestrator/stage/membership_init.rs`):

- deps `[CollectPubkeys]` (:17-19); `applies_to_roles [Exit]` (:20-22); fanout `Once` (:23-25).
- `execute` (:27-74): finds the exit alias from assignments (hard error `'no Exit node in assignments'` if absent); calls `build_membership_peers(ctx)` (:39); then on the **exit adapter**: `issue_membership_owner_key()` → `init_membership_snapshot(key, &peers)`; on success stores the returned snapshot bytes in `ctx.membership_snapshot` (:70).

`build_membership_peers` (:77-141) per-assignment requirements (all hard errors):

| Requirement | Error string | Windows exposure |
| --- | --- | --- |
| `ctx.node_ids[alias]` non-empty | `missing/empty node_id` | filled at `collect_node_id` |
| `ctx.collected_pubkeys[alias]` valid 64-hex | `missing/invalid WireGuard public key` | filled by the **fixed** `70e16a63` path |
| `ctx.collected_gossip_identities[alias]` present | `missing gossip identity` | Windows returns `GossipIdentity::DeferredPlatform` ALWAYS (`adapter/windows.rs:158-161`), which counts as present |
| Linux + `DeferredPlatform` | `… is Linux but reported no gossip identity` | Linux-only check; Windows passes by construction |

So on Windows the gossip-identity precondition is **vacuously satisfied by design**: `collect_gossip_identity` returns `DeferredPlatform` unconditionally because Windows has no gossip transport (the daemon refuses a configured gossip secret; unix-only, `windows.rs:158-161`).

### 3.2 Windows adapter side

`adapter/windows.rs:139-149` routes both calls into `windows_membership.rs`:

- `issue_membership_owner_key` (:24-49): PowerShell `Test-Path` + `Get-Content -Raw` on `C:\ProgramData\RustyNet\membership\membership.owner.key.pub`, trimmed; **fails closed** with `'membership owner public key is empty on remote; has membership been initialized?'` if empty.
- `init_membership_snapshot` (:62-130):
  - Derives `exit_node_id` from the peers list (the peer with role `Exit`); `approver_id = format!("{exit_node_id}-owner")` (:74-78).
  - Doc (:51-61): the initial snapshot already exists — it is created by `rustynetd membership init` during the **bootstrap_hosts** stage (see §3.3).
  - For every **non-exit** peer runs `rustynetd membership add-peer` (:81-94): owner signing key `membership\membership.owner.key`, DPAPI passphrase blob `secrets\signing_key_passphrase.dpapi` (distinct from the WG passphrase; fail-closed if they collide, :81-88); pubkey hex-32 validated (`hex_32_arg`, :93, :328-336); capabilities via `role_capability_csv` (:94); args `ps_quote`'d (RSA-0059, tests :432-463); `MEDIUM_TIMEOUT` = 120 s per peer (:18-19, :117).
  - Exit peers are **skipped** (:90-92) — the exit is the genesis snapshot's only member already.
  - Reads the snapshot back: `[Convert]::ToBase64String([System.IO.File]::ReadAllBytes(<WINDOWS_MEMBERSHIP_SNAPSHOT_PATH>))` (:121-127), base64-decodes via a **local host** `base64 -d` subprocess (:338-369), returns `MembershipSnapshot{data}`.

### 3.3 Daemon side — where the artifacts come from

Bootstrap script (`orchestrator/adapter/windows_install.rs:979-1100`), section `── 2. WireGuard key init + membership init + service start ─`, all under one SSH session with `$ErrorActionPreference='Stop'`:

1. Two independent 48-hex passphrases from separate `RNGCryptoServiceProvider` instances (WG vs membership signing; collision → throw `fail-closed: WG + signing passphrases collided (RNG bug)`, :1044-1056). Plaintext staged only to per-key tempfiles under the credentials workspace (:1057-1062).
2. `rustynetd key init --passphrase-file <wg plaintext> --force` (:1063).
3. `rustynetd membership init --snapshot … --log … --watermark … --owner-signing-key <owner key> --owner-signing-key-passphrase-file <signing plaintext> --node-id <node_id> --network-id <network_id> --force` (:1065-1073; throw `rustynetd membership init failed: …` on failure).
4. DPAPI-protect both plaintexts (LocalMachine scope) and write `wireguard.passphrase.dpapi` + `signing_key_passphrase.dpapi` atomically (:1075-1086); plaintexts cleared/removed in `finally` (:1089-1094).
5. `rustynetd windows-runtime-acls-check` gate (:1095-1096) — throw `runtime ACL check failed (startup would fail)`.

The **service is deliberately NOT started here** (:994-999): the verifier keys (`assignment.pub`, `traversal.pub`, `dns-zone.pub`) are required by the daemon at startup but are only distributed by the three `distribute_*` stages that run after bootstrap. First daemon start happens at `enforce_baseline_runtime`.

Daemon-side `rustynetd membership init` (`crates/rustynetd/src/main.rs:4480-4601`):

- `owner_approver_id = format!("{node_id}-owner")` (:4484) — matches the orchestrator's derivation iff the exit peer's `node_id` equals the `--node-id` passed at bootstrap; both come from `ctx.node_ids[windows alias]` (same source), so consistent.
- Persists the encrypted owner signing key (:4486-4491).
- Genesis `MembershipState`: epoch 1, single node (the exit) with the **full** capability set incl `Client` / `ExitServer` / `RelayHost` + Anchor sub-caps (:4498-4532). Comment: without `Client` every non-exit node fails `validate_node_role_membership_alignment` (preflight exit 65) at first boot; the real snapshot overwrites non-exit nodes during `DistributeMembership`.
- Approver set = single Owner approver (`{node_id}-owner`), quorum threshold 1 (:4533-4540); genesis head attestation minted and signed (:4544-4565); snapshot persisted (:4566-4571); log file written `write+create+TRUNCATE` with content `version=1\n` (:4573-4582).
- **Then (:4590-4594):** `std::fs::write` of the owner public key to `membership.owner.key.pub` — a **plain, non-atomic** write of the exact file `issue_membership_owner_key` later reads. This is the closest surviving analog of the fixed `collect_pubkeys` bug (§6.1).

Peer add (`run_membership_add_peer`, `main.rs:4026-4276`, routed :4002):

- All paths must be absolute (:4139-4142); passphrase read via `read_passphrase_file_explicit` (auto-decrypts DPAPI on Windows, :4144-4147); signing key decrypted + 32-byte check + zeroized (:4162-4168).
- **Idempotent**: node already present → `already present in snapshot; no-op`, exit 0 (:4174-4178).
- Else an `AddNode` update (roles `["tag:members"]`, status Active, :4186-4195), `update_id = add-peer-{node_id}-{now}` (:4206), expires +86400 s (:4207), signed by the approver with head attestation in the same session (:4223-4236); replay cache seeded from existing log entries, duplicate `update_id` rejected (:4242-4256); apply → append log → persist snapshot (:4258-4269).

### 3.4 Fresh-guest preconditions and how they could be violated

| Precondition at `membership_init` | Producer | Violation mode |
| --- | --- | --- |
| `membership.owner.key.pub` exists and is non-empty | `rustynetd membership init` at bootstrap (:4590-4594) | bootstrap step 3 failed but its throw was missed (it throws on nonzero, :1065-1073); or a **partial prior bootstrap** left a stale/empty file. Fail-closed error message names the file, so this is loud. |
| `membership.owner.key` decryptable with `signing_key_passphrase.dpapi` blob | bootstrap steps 1+3+4 | **Key mismatch window** (§6.4): a partially-failed bootstrap can leave a NEW owner key with the OLD DPAPI blob → `add-peer` decrypt error. |
| `membership.snapshot` loadable + log header `version=1` | bootstrap step 3 (`TRUNCATE` + `version=1`) | corrupted/partial file → snapshot load error at :4171. |
| Exit alias in assignments with collected node_id + pubkey | `collect_pubkeys` (fixed) | if collection returned a stale file-read value pre-fix — no longer applicable at this commit. |
| All peers have a gossip identity | adapter returns `DeferredPlatform` always | structurally satisfied on Windows. |

## 4) `distribute_membership`

`DistributeMembershipStage` (`orchestrator/stage/distribute_membership.rs`): deps `[MembershipInit]` (:16-18); fanout `PerNode` (:19-24). Requires `ctx.membership_snapshot` (error: `no membership snapshot in context (MembershipInit must run first)`, :26-72); writes a local tmp `rn_membership_<pid>.snapshot` (:36-43); targets **non-exit** nodes only (:45-50); per node `adapter.distribute_signed_bundle(Membership, tmp)` (:52-64).

**Topology consequence:** in the typical `--node` topology `windows-x86-1` **is the exit**, so Windows receives **no** membership snapshot — the clients (Linux/macOS) do. An exit-only run passes trivially (test :112-143).

Windows distribution mechanics (`windows_membership::distribute_signed_bundle`, :135-186): staging dir `C:\Windows\Temp\rustynet-stage` (kept **outside** ProgramData so the hardened service-only ACL cannot inherit onto SCP-staged files, `windows_install.rs:19-23`); `scp_to` staging; for `Membership` only, initializes the log header `version=1` **if the log is missing or zero-length** (:163-175; header format pinned by test :427-429); install = `Move-Item -LiteralPath <staging> -Destination <dst> -Force` under `Set-StrictMode` + `ErrorActionPreference Stop` (:176-183) — same-volume rename on `C:`, atomic.

## 5) `anchor_validation` and `admin_issue` (T1Role, brief)

### 5.1 `anchor_validation` (`orchestrator/stage/anchor_validation.rs`)

- deps `[DistributeMembership]` (:127-129), applies `[Anchor]`, PerNode. Self-filters Anchor nodes from assignments (:139-144); **none → `StageOutcome::Skipped('no node in this topology is assigned the anchor role')`** (:150-154) — deliberately `Skipped`, not `Passed`, so the run goes Partial (fail-closed, :146-149).
- Per anchor node: node_id required fail-closed (:178-184).
- **Windows-real part:** capability advertisement validation runs cross-OS — `validate_anchor_capability_advertisement(&*shell, platform, node_id)` (:196-201), a parser-only check of `rustynet anchor list` over the `RemoteShellHost` seam, with per-OS membership snapshot/log paths (Windows: `DEFAULT_WINDOWS_MEMBERSHIP_SNAPSHOT_PATH` / `LOG_PATH`, see `orchestrator/role_validation/anchor.rs:121-122`, :879-883).
- **Windows-named-skip part:** runtime bundle-pull substages gate on `runtime_coverage(platform, ctx.macos_anchor_validators_elected)` (:220, pure fn :290-307): `!anchor_lab_runtime_implemented(platform)` → `ReportedSkip`; Linux → Inline; macOS+elected → Delegated; **everything else, including Windows → `ReportedSkip`** (:305, outcome :242-244). Any reported skip → stage outcome `Skipped` (:327-338: failures → Failed; any runtime skip → Skipped; else Passed) — the run goes **Partial by design**, never a silent pass. `ANCHOR_REPORTED_SKIPS_NOTE` (:57-72) documents why: anchor mutation substages (gossip priority, downgrade revocation) are pending the Windows membership-mutation backend; the enrollment endpoint is deferred (authorisation gate enforced in the daemon; LAN listener not built — `AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md` §7). The skip note is written best-effort to `<report_dir>/anchor_validation.reported_skips.json` on pass (:74-76, :390-399).

### 5.2 `admin_issue` (`orchestrator/stage/admin_issue.rs` + `orchestrator/role_validation/admin_issue.rs`)

- deps `[DistributeMembership]` (:17-19), applies `[Admin]`, PerNode; no admin aliases → `Skipped` (:35-39).
- `validate_admin_issue` (`role_validation/admin_issue.rs:8-57`): polls `shell.run_argv(&["/usr/local/bin/rustynet", "status"])` up to 4 attempts × 3 s, requires a stdout line `node_role=admin`, then runs `peer-list`; fail-closed on nonzero exit.
- **Latent Windows gap:** the binary path `/usr/local/bin/rustynet` is **hard-coded** (:9-10, :16, :46-48) and does not exist on Windows (Windows binary = `C:\Program Files\RustyNet\rustynet.exe`, `RUSTYNET_PATH`, `windows_install.rs`). `admin_issue_runtime_implemented` returns `true` for **all** platforms including Windows (:4-6, pinned by test :82-86), so a Windows **admin-role** node would fail 4× command-not-found → stage Failed. In the typical topology `windows-x86-1` is Exit and admin is a Linux node, so the stage never touches Windows today — but the platform gate is lying about Windows support.

## 6) File-based reads/writes with the `collect_pubkeys` risk pattern

The fixed defect: a file written by one process at one moment, read by another at a different moment, with no atomicity/staleness guard. Ranked by similarity × reachability:

### 6.1 `membership.owner.key.pub` — plain non-atomic write, later remote read (closest analog; low practical risk)

- **Writer:** daemon `rustynetd membership init`, `std::fs::write` directly to `membership.owner.key.pub` — **not** temp+rename (`main.rs:4590-4594`).
- **Reader:** orchestrator `issue_membership_owner_key` via PowerShell `Get-Content -Raw` (`windows_membership.rs:24-49`), a **separate stage later** (`membership_init` runs after `bootstrap_hosts` completes, including its `windows-runtime-acls-check` gate).
- Assessment: exactly the fixed pattern (non-atomic cross-process file handoff), but the write is followed by the remainder of the bootstrap script in the same SSH session before any reader runs, and `membership init` completes before stdout returns. A torn read requires the daemon to have been killed mid-write — not reachable through the normal stage sequence. **Flag: yes; risk: low.**

### 6.2 Snapshot read-back after `add-peer` loop (low risk)

`init_membership_snapshot` reads `membership.snapshot` via base64 PowerShell read (:121-127) only after the sequential per-peer `add-peer` calls (each `MEDIUM_TIMEOUT` 120 s) complete; the last writer is the same-session `rustynetd membership add-peer` child (`persist_membership_snapshot_with_attestation`, `main.rs:4258-4269`). Sequential, bounded, no concurrent writer. **Flag: same family; risk: low.**

### 6.3 Tunnel-IP readiness vs SCM Running (real race, actively mitigated)

`enforce_daemon` waits up to 100 s on a tunnel-IP readiness fragment after `start_daemon` because "SCM reports Running before the daemon thread begins its first reconcile" (`windows_install.rs:540-552`). `start_daemon` itself only polls SCM state (:556-575). This is a state-machine handshake (service control manager vs daemon reconcile loop), mitigated by polling rather than a file flag — the correct shape, but it is the one place in this window where a genuine asynchrony is known to exist. **Flag: mitigated; keep the wait.**

### 6.4 Bootstrap-internal window: signing passphrase plaintext vs DPAPI blob (real window, self-healing)

`rustynetd membership init` consumes the **plaintext** signing passphrase (:1065-1073) *before* the DPAPI blob `signing_key_passphrase.dpapi` is (re)written (:1081-1086). A failure between the two leaves a new owner key + old blob; a later `add-peer` then fails decryption (§3.4 row 2). Mitigation: any re-run regenerates both with `--force`, and bootstrap aborts loudly on step failure (`$ErrorActionPreference='Stop'`). **Flag: yes; risk: low (requires mid-script abort).**

### 6.5 Bundle issuance: local `fs::write` → scp → guest rename + digest check (mitigated)

`issue_*_bundles_locally` writes bundle + verifier files with plain `fs::write` into a local temp dir (`ops_e2e.rs:3492-3666`) — non-atomic, but local to the orchestrator process and consumed only after issuance returns. The distribute stage then validates the verifier key hex locally (`validated_verifier_key_sha256`, `distribute_assignments.rs:219-227`) and the Windows guest re-hashes the installed verifier file (`Get-FileHash` compared lowercase, throw `verifier key digest mismatch`, `windows_membership.rs:218-228`). Double end-to-end verification. **Flag: pattern present; mitigated.**

### 6.6 Membership log header vs daemon appends (no real race)

Orchestrator writes the `version=1` header only when the log is missing/empty (:163-175); the daemon truncates-creates it at `membership init` (:4573-4582) and **appends** thereafter (`append_membership_log_entry`). Stages are sequential, so concurrent append cannot occur; a stale header from a prior run is overwritten by the bootstrap `TRUNCATE`. **Flag: no.**

## 7) `distribute_assignments` / `distribute_traversal` / `distribute_dns_zone` on Windows

All three share `distribute_bundle_kind` (`orchestrator/stage/distribute_assignments.rs:163-264`; traversal :42-43, dns-zone :42-43):

1. Find exit alias (error `no Exit node in assignments`).
2. `build_bundle_env` (:56-160): `NODES_SPEC` = `node_id|endpoint|pubkey_hex|caps_csv` per node — endpoint falls back to `0.0.0.0:51820` when `ctx.endpoints` lacks the alias (:73-77; endpoints are recorded at `collect_pubkeys`, `context.rs:202-204`); capabilities are **platform-aware** (`product_capabilities_for_platform`); `ALLOW_SPEC` = full mesh (:89-107); `ASSIGNMENTS_SPEC` = `nodeid|exit_nodeid` with `-` for Exit/BlindExit (:134-156); TTL 86400 s (Assignment/Traversal) / 300 s (DnsZone).
3. `exit_adapter.issue_bundles_to_dir(kind, env, tmp_dir)` (:199) — **on Windows this never touches the guest**: the adapter generates an ephemeral signing key in the orchestrator process and issues bundles locally via `issue_assignment_bundles_locally` / `issue_traversal_bundles_locally` / `issue_dns_zone_bundles_locally` (`adapter/windows.rs:292-323`; rationale comment :298-302: the Windows `rustynet.exe` supports only daemon-control subcommands, the full ops CLI is Linux-only). **Linux/macOS contrast:** their adapters run the remote `ops e2e-issue-*-bundles-from-env` path on the guest.
4. Verifier key `rn-<kind>.pub` validated locally (fail-closed `issued {kind} verifier key invalid`, :219-227).
5. **Strict two-phase barrier** (`run_verifier_barrier`, :228-256, :268-304): `distribute_verifier_key` to **every** node (Windows included) must complete for all nodes before any `distribute_signed_bundle` begins; shutdown-aware bounded parallelism. Bundle filename `rn-<prefix>-<node_id>.<ext>` must exist or error `bundle not found`.

Windows receive path (`windows_membership.rs`):

- `distribute_verifier_key` (:192-230): local sha256 of the pub file, `windows_verifier_key_paths` (:234-255: Assignment→`trust\assignment.pub`, Traversal→`trust\traversal.pub`, DnsZone→`trust\dns-zone.pub`, Membership→`trust\membership.pub`), scp to staging `rn-<kind>.pub`, guest install via `Move-Item -Force`, then `Get-FileHash` digest check (:218-228).
- `distribute_signed_bundle` (:135-186): dst paths `trust\rustynetd.assignment` / `.traversal` / `.dns-zone` (:257-278), staging + `Move-Item -Force` atomic rename; membership log-header logic only for the Membership kind.

Local issuance details (`ops_e2e.rs:3492-3666`, all three confirmed): env parsed strictly (duplicate key → error, :3476-3478); required keys `NODES_SPEC`/`ALLOW_SPEC` (+`ASSIGNMENTS_SPEC` for assignment) missing → error; `ensure_safe_spec` on each; TTL defaults enforced (assignment 300, traversal 120, dns-zone fixed 300) with loud failure on malformed values; ephemeral 32-byte signing secret from `OsRng`, zeroized after (:3483-3490). Output filenames `rn-assignment-{target_node_id}.assignment` + `rn-assignment.pub`, `rn-traversal-{node_id}.traversal` + `.pub`, `rn-dns-zone-{subject_node_id}.dns-zone` + `.pub` — **matching** the `rn-<prefix>-<node_id>.<ext>` the barrier expects (verified; scheme drift would surface as `bundle not found`).

## 8) `enforce_baseline_runtime` (first daemon start on Windows)

`EnforceBaselineRuntimeStage` (`orchestrator/stage/enforce_runtime.rs`): deps `[DistributeDnsZone]` (:32), fanout PerNode, applies all roles; runs `enforce_runtime` on **every** node alias in parallel; adapter errors are enriched best-effort with `collect_daemon_failure_reason()` output appended as `| daemon: {reason}` (:34-72; Windows impl `windows_traffic::collect_daemon_failure_reason`, routed `windows.rs:267`).

Windows `enforce_daemon` (`windows_install.rs:521-554`), three steps:

1. Patch `--auto-tunnel-enforce` into the `RUSTYNETD_DAEMON_ARGS_JSON` line of `C:\ProgramData\RustyNet\config\rustynetd.env` (`build_auto_tunnel_enforce_patch_script`, :470-519; also injects `--traversal-stun-servers <gateway-ipv4>:3478` when the gateway IP matches an IPv4 regex); `SHORT_TIMEOUT`.
2. `stop_daemon` (`Stop-Service -Force SilentlyContinue`) then `start_daemon` — clean start so the daemon reads `--auto-tunnel-enforce true` (a plain `sc.exe start` would no-op with exit 1056 on a running service). See §9 for the stale comment here.
3. Tunnel-IP readiness wait (100 s, :540-552, §6.3).

`start_daemon` (:556-575) polls SCM via `windows_service_start_probe_fragment` (handles already-running exit 1056; 30 s stop-poll + 60×2 s start-poll; timeout 210 s).

Daemon startup requirements at this point (why the ordering matters): the daemon needs the verifier keys `trust\assignment.pub` / `traversal.pub` / `dns-zone.pub` plus bundles `rustynetd.assignment` / `.traversal` / `.dns-zone` plus `membership.snapshot` / log / watermark all present (`windows_install.rs:994-999` comment; `windows_paths.rs:40-57` defaults), and runs the fail-closed 9-root ACL gate `validate_windows_runtime_startup_acls` (`windows_paths.rs:144-173`, roots :262-275, test pins 9 :1043-1067) — drift in any reviewed root's DACL/owner refuses startup. Membership/trust state loading is the same signed-state path as Linux behind cfg-selected Windows path constants (`daemon.rs:91`, :228; mesh-status side: `windows_mesh_status.rs:80` W8 fail-closed state-path review, unknown-tag fail-closed :544-548).

## 9) Stale comments / misleading docs in this window

- **`enforce_daemon` comment vs bootstrap reality** (`windows_install.rs:530-537` vs :994-999): the enforce comment says "The daemon was started during bootstrap with `--auto-tunnel-enforce false` and is still running", but the bootstrap script explicitly does **not** start the service (:994-999) — the first start happens here. Behaviorally harmless (Stop on a non-running service is `SilentlyContinue`; the start probe handles 1056), but the comment describes a bootstrap that no longer exists. Same class as the stale comments catalogued in the `collect_pubkeys` analysis.
- `windows_membership.rs` carries `#![allow(dead_code)]` while being the live implementation for these stages — the allow is stale relative to its actual usage (cosmetic; no behavior impact).
- The remote `windows_traffic::issue_bundles_to_dir` variant (:988-1087) is dead for this path — the adapter never calls it (the local-issuance variant replaced it); it survives as a misleading near-duplicate.

## 10) TODO / unimplemented / quiet no-op scan

Grep for `TODO|FIXME|unimplemented!|todo!` across `crates/rustynet-cli/src/vm_lab/orchestrator/` → 62 matches, **all in test mock adapters** (`diagnostics.rs:742+`, `stage/cross_network.rs:1634+`, `stage/collect_pubkeys.rs:213+` — the "every other method is `unimplemented!()`" test-adapter pattern). **Zero** in `adapter/windows.rs`, `windows_install.rs`, `windows_membership.rs`, `windows_traffic.rs`. No quiet no-op stubs in the Windows post-pubkeys path; the two named limitations are `anchor_validation`'s Windows `ReportedSkip` (loud, run goes Partial) and `admin_issue`'s hardcoded Unix path (§5.2 — a wrong-path failure, not a silent skip).

## 11) Ranked best-guess: what fails first in the live run

Grounded ranking, most→least likely to be the **first** failure after the `collect_pubkeys` fix:

1. **`issue_membership_owner_key` → `'membership owner public key is empty on remote; has membership been initialized?'`** (`windows_membership.rs:24-49`) — only reachable if the bootstrap's own `membership init` throw (:1065-1073) somehow didn't fire on a broken guest; loud, self-describing. In practice bootstrap fails first if init fails, so this is the "second line of defense" failure.
2. **`add-peer` DPAPI/signing-passphrase decrypt failure** at `membership_init` on a **re-run after a partial bootstrap** (§6.4 window: new owner key + old blob). First-run-fresh: not reachable. Highest-probability failure *of this stage* on a dirty guest.
3. **`admin_issue` hardcoded `/usr/local/bin/rustynet`** — fails instantly **iff** the topology assigns Admin to a Windows node (command-not-found ×4 → Failed, §5.2). Topology-dependent latent gap, not a `windows-x86-1`-as-Exit failure.
4. **`distribute_*` barrier `bundle not found`** — only if the local-issuance filename scheme drifts from `rn-<prefix>-<node_id>.<ext>`; verified matching at this commit (`ops_e2e.rs:3492-3666` vs barrier expectation), so unlikely without a code change.
5. **`enforce_baseline_runtime` daemon start failure** — missing verifier key/bundle (would indicate an ordering bug; the strict barrier makes this near-impossible), or the **9-root ACL gate** refusing startup on DACL drift (plausible on an aged/imaged guest), or the `rustynetd.env` args patch failing. The failure reason is appended to the stage error (`| daemon: {reason}`), so it will be diagnosable from the report.
6. **`anchor_validation` → run Partial by design** on Windows (`ReportedSkip`, §5.1) — not a failure, but it caps the run verdict at Partial on any topology containing a Windows anchor; with no anchor at all it is also `Skipped`. Expect this in the matrix and do not read it as a defect.
7. **`membership_init` peer-precondition errors** (`missing/invalid WireGuard public key`, `missing gossip identity`) — structurally covered post-`70e16a63` (status-response key source; `DeferredPlatform` always present). Listed last because nothing in the current code reaches them.

## 12) Proposed fixes (NOT implemented — this document changes nothing)

1. `admin_issue`: replace the hardcoded `/usr/local/bin/rustynet` with the platform adapter's binary path (Windows: `RUSTYNET_PATH` = `C:\Program Files\RustyNet\rustynet.exe`), or return a truthful `runtime_implemented=false` for Windows until proven — the current `true`-for-all gate plus Unix path is fail-loud but mislabeled.
2. Bootstrap atomicity (§6.4): write the DPAPI signing blob **before** running `membership init` with the plaintext (order: protect → write blob → run init), or regenerate the blob deterministically from the same plaintext on every run (already true) and document the rerun-heals property at :1065.
3. `main.rs:4590-4594`: write `membership.owner.key.pub` via the same temp+rename pattern used elsewhere (`persist_owner_signing_key_encrypted`) to close the last non-atomic cross-process handoff in the window.
4. `enforce_daemon` comment (:530-537): rewrite to match the actual sequence (service not started at bootstrap; this stop/start is the first start).
5. Consider removing or clearly marking the dead remote `windows_traffic::issue_bundles_to_dir` variant (:988-1087) to prevent future confusion with the live local-issuance path.

## 13) Evidence index

- Stage catalog/order: `orchestrator/stage/mod.rs:174-214`; `orchestrator/plan.rs:996-1003`, `:405-423`, `:1114-1115`
- `membership_init`: `orchestrator/stage/membership_init.rs:17-25, :27-74, :77-141`
- Windows adapter surface: `orchestrator/adapter/windows.rs:100-279` (gossip `DeferredPlatform` :158-161; local issuance :292-323; daemon fns :114-135)
- Windows membership: `orchestrator/adapter/windows_membership.rs:18-19, :20, :24-49, :51-61, :62-130, :135-186, :192-230, :234-255, :257-278, :280-282, :291-326, :328-336, :338-369, :427-429, :432-463`
- Windows install/bootstrap: `orchestrator/adapter/windows_install.rs:15-44, :19-23, :65-69, :470-519, :521-554, :530-537, :540-552, :556-585, :588-629, :979-1100` (bootstrap sequence :1044-1096; not-started comment :994-999)
- Daemon membership init: `crates/rustynetd/src/main.rs:4480-4601` (owner pubkey non-atomic write :4590-4594); `run_membership_add_peer` :4026-4276 (idempotence :4174-4178; replay :4242-4256)
- Daemon paths/ACL gate: `crates/rustynetd/src/windows_paths.rs:5-70, :40-57, :144-173, :262-275, :1043-1067`; `daemon.rs:91, :228`; `windows_mesh_status.rs:80, :544-548`
- `distribute_membership`: `orchestrator/stage/distribute_membership.rs:16-24, :26-72, :112-143`
- `distribute_assignments` (+shared kind): `orchestrator/stage/distribute_assignments.rs:33-41, :56-160, :73-77, :89-107, :114-126, :134-156, :163-264, :199, :219-227, :228-256, :268-304`; traversal/dns-zone reuse :42-43
- Local issuance: `crates/rustynet-cli/src/ops_e2e.rs:1308-1313, :2891-2898, :3064, :3476-3478, :3483-3490, :3492-3666`
- `anchor_validation`: `orchestrator/stage/anchor_validation.rs:57-76, :91-93, :121-122, :127-132, :137-257, :196-201, :220, :242-244, :290-307, :305, :327-338, :390-399, :879-883`; `orchestrator/role_validation/anchor.rs:121-122`
- `admin_issue`: `orchestrator/stage/admin_issue.rs:17-22, :35-39`; `orchestrator/role_validation/admin_issue.rs:4-10, :16, :46-48, :82-86`
- `enforce_baseline_runtime`: `orchestrator/stage/enforce_runtime.rs:32, :34-72`
- Dead remote issuance variant: `orchestrator/adapter/windows_traffic.rs:988-1087`
- Predecessor analysis: `documents/operations/active/WindowsCollectPubkeysEmptyReadAnalysis_2026-09-04.md`
