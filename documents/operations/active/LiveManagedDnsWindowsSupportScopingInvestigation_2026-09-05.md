# `live_managed_dns_validation` on Windows — scoping investigation (what the validator does, what is POSIX-locked, what already exists)

- Status: analysis (docs-only; no code changed by this document)
- Date: 2026-09-05
- Scope: static code trace of the orchestrator stage `live_managed_dns_validation` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/live_managed_dns_validation.rs`) and the validator binary it shells out to, `crates/rustynet-cli/src/bin/live_linux_managed_dns_test.rs`, to scope what a Windows-compatible version would need. Companion to `WindowsPostEnforceRuntimeLiveStagesAnalysis_2026-09-05.md` (which flags this stage's Windows rejection at its §7 survey) and `WindowsMembershipInitPostPubkeysAnalysis_2026-09-05.md`.

> ## UNTRUSTED
>
> This document was produced by a delegated AI edit agent as a **static code trace**, not from a live-lab run. It contains no live-lab evidence: every claim below is a reading of the source at the commit this worktree branched from (`8547f6c1`). Line numbers refer to that tree and **will drift** as code changes. Treat every conclusion as a hypothesis to verify against the real code and a real run before acting on it.

## 1) The gate being investigated

`LiveManagedDnsValidationStage::execute` (`live_managed_dns_validation.rs:29-146`) resolves the topology's `exit` role as "signer" and its `client` role as "client" (`:30-37`, `ssh_params_for_role` at `:164-190`, with per-platform default SSH users at `:174-182` — Windows defaults to `administrator`), refuses a same-node signer/client (`:76-81`), then **rejects any topology containing a Windows node outright**: `reject_unsupported_platforms` (`:288-304`), called at `:73-75`. The rejection message and its doc comment (`:282-287`) say the validator "reads each node's assignment bundle over sudo/sh -lc, and its wireguard.pub from a POSIX state root. Neither exists on Windows," and that omitting the node is not a fallback because the full-mesh assignment bundle names it either way.

Everything real happens in a separate binary invocation (`:88-121`):

```
cargo run -p rustynet-cli --features vm-lab --bin live_linux_managed_dns_test --
  --ssh-identity-file <id> --known-hosts-file <kh>
  --signer-host <user@exit> --signer-node-id <id>
  --client-host <user@client> --client-node-id <id>
  --ssh-allow-cidrs <cidrs> --report-path <json> --log-path <log>
  [--managed-peer <node-id|user@host|platform> ...]
```

Two details matter for a Windows port and are often missed:

- The stage is **already platform-aware on the argument side**: `managed_peer_args` (`:239-280`) appends the node's `VmGuestPlatform` as a third `|`-separated field (`:273-278`), and `platform_str` (`:192-199`) maps `Windows` cleanly. Only `reject_unsupported_platforms` blocks the path.
- The comment at `:232-238` explicitly forbids platform-filtering the managed-peer set (it must stay a superset of the assignments or the validator's own `validate_targets` re-fails on "references unmanaged peer"), so a Windows fix must teach the validator to *handle* a Windows node, not skip it.

## 2) What the binary actually validates (end to end)

The binary (`live_linux_managed_dns_test.rs`, 3523 lines in this tree) proves the **managed DNS (Magic DNS) zone pipeline**: a signer issues a signed `dns-zone` bundle, the client installs it, the client's resolver stack serves the zone's names, and the fail-closed path rejects invalid bundles. `run()` (entry `:66`, body `:116-920`):

1. **Config + platform map.** `Config` carries a global `--platform` (`:962-963`, default `Linux` at `:943`), and a per-node map `platform_by_node` is built from signer, client, and every `--managed-peer` (`:178-190`; peers parse their platform from the spec, `parse_managed_peer_spec` `:2778+`). This map is what per-node work (bundle reads, re-push) branches on.
2. **Sudo priming.** `ctx.push_sudo_password` on both hosts (`:148`), which calls `verify_sudo` — see §3; this is the first thing that dies on Windows.
3. **Baseline daemon status** on the client (`:153-157`) with `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock`.
4. **Zone issuance on the signer.** A passphrase temp file is made remotely (`mktemp /tmp/rn-dns-zone-passphrase.XXXXXX`, `:268-270`); `issue_dns_bundle` (`:1138-1184`) runs `rustynet ops … zone` on the signer against `/etc/rustynet/membership.owner.key` (`:1140-1165`) and produces four bundles — valid, stale, replay, policy-invalid (`:325-361`) — plus the zone verifier pubkey (`:369`). Four more adversarial variants (forged, tampered) are minted locally for negative checks (`:410-415`), and the binary re-verifies the issued bundles locally through `rustynet ops … zone --expected-zone-name` (`:427-485`).
5. **Install on the client.** Bundles are scp'd to `/tmp` (`:1220-1221`), then `install(1)` places the verifier key at `/etc/rustynet/dns-zone.pub` (`:1233-1234`), the bundle at `/var/lib/rustynet/rustynetd.dns-zone` (`:1247-1248`), the watermark (`:1257-1258`), and cleans `/tmp` (`:1259-1266`).
6. **Positive resolver checks on the client** (the heart of the stage):
   - Split-DNS configuration inspection (`:518-525`): `capture_resolver_config_status` (`:2215-2248`) — Linux `resolvectl status <iface>`, macOS `scutil --dns`, **Windows `Get-DnsClientServerAddress` via PowerShell emitting `<ifAlias>=<server>` rows** (`:2235-2246`).
   - Loopback-resolver query via the OS-independent `rustynet ops` JSON path (`:526-533`) and a direct alias query (`:533`).
   - Resolver-cache flush (`:541`, `flush_os_resolver_cache` `:2254-2298`): `resolvectl flush-caches` / `dscacheutil -flushcache` / **Windows `Clear-DnsClientCache`**.
   - System-resolver answer probe (`:549-550`, `capture_os_resolver_answer` `:2299-2360`): Linux `resolvectl query` (under `sh -lc`, `:2311`), macOS `dig @127.0.0.1 -p 53535` + `dscacheutil` (`:2318-2322`), **Windows PowerShell `Resolve-DnsName -Server 127.0.0.1`** (`:2339`).
   - External control query for `example.com` (`:540`) to prove the mesh resolver does not answer the world.
7. **Traversal-bundle distribution to managed peers** (`:1276-1436`): the signer re-issues traversal bundles over the authorized allow-pairs (`build_authorized_allow_spec` `:1542-1571`, fed by every node's assignment bundle — see step 9), scp'd and installed to `/etc/rustynet/traversal.pub`, `/var/lib/rustynet/rustynetd.traversal`, plus a watermark (`:1393-1415`). The per-node re-push loop **skips non-Linux peers by design** ("setup-distributed bundles stay fresh under the 86400s lab window", `:678-691` and `:1318-1330`) — a Windows peer is not expected to receive a re-push, it is expected to already hold its setup-distributed bundle.
8. **Fail-closed adversarial cases** (`exercise_invalid_bundle_case` `:1788+`): install each invalid bundle, expect the client's `rustynet … dns inspect` to read back `state=invalid` (`wait_for_dns_inspect_state` `:2027-2066`, matchers `:2067-2098`), expect DNS queries to fail closed (`dns_query_failed_closed` `:2113`), with diagnostic captures of the managed-DNS service state, hosting daemon state, and daemon log tail between cases (`capture_managed_dns_service_state` `:2363-2392`, `capture_hosting_daemon_state` `:2404-2438`, `capture_daemon_log_tail` `:2452-2493` — all three already have Windows branches, §3.2), and a full service restart between cases (`restart_managed_dns_stack` `:1466-1532`), then restore the valid bundle (`restore_valid_bundle_after_invalid_case` `:1952-1998`).
9. **Assignment-scope cross-check over every node** (`:202`, `capture_assignment_authority_scopes` `:1573-1600`): `cat` each node's assignment bundle — path selected **per platform** by `assignment_bundle_path` (`:2814-2824`), which **already returns the Windows path `C:\ProgramData\RustyNet\trust\rustynetd.assignment`** — and cross-check subject/peer references.
10. **Signer trust refresh** (`:150`, `:750`; `refresh_signer_trust_evidence` `:1533-1540`): `rustynet ops refresh-signed-trust` on the signer.
11. **Verdict assembly** (`:755-812`, report fields `:838-881`): pass requires the zone-issue verification to pass, the resolver config to advertise the managed zone (`resolver_config_advertises_managed_zone` `:2507-2569`, including the Windows-specific parser `windows_dns_client_lists_loopback_server` `:2556-2570`), the loopback query to answer, the system resolver to return the expected IP (`os_resolver_answer_contains_ip` `:2571+`), the alias to resolve, and the managed resolver service to be active (`managed_dns_service_active` `:2611+`; Windows branch `(Get-Service -Name 'RustyNet').Status` consumed at `:2382-2390`). Report JSON lands at `--report-path`.

## 3) Which operations are POSIX-locked vs already portable

### 3.1 The one true blocker: the transport

Every remote operation in the binary goes through `LiveLabContext` helpers in `crates/rustynet-cli/src/bin/live_lab_support/mod.rs`, and **all of them hardcode POSIX elevation**:

- `run_root` (`:1085-1090`), `run_root_allow_failure` (`:1092`), `capture_root` (`:1099-1104`), `capture_root_allow_failure` (`:1106+`), and the `_with_retry` variants (`:1177`, `:1199`) all first probe `ssh … sudo -n -k true` and then exec `sudo -n <argv>`.
- `verify_sudo` (`:1253-1273`) fails closed with "passwordless sudo (sudo -n) is required for live lab automation on {target}"; `push_sudo_password` (`:1275-1283`) calls it. The binary's first remote act (`:148`) therefore fails immediately on Windows OpenSSH (no `sudo` binary).
- PATH resolution of the remote `rustynet` CLI goes through `sh -lc` login-shell wrappers (`:971`, `:1654`), precisely because `sudo`'s `secure_path` drops `/usr/local/bin` on the RHEL family (`:85-86`, `:456`, `:1785`).

Consequence: the binary's Windows PowerShell probe branches (below) are currently **dead code** — even `Get-DnsClientServerAddress` would be launched as `ssh host sudo -n powershell …`, which cannot work. The orchestrator's doc comment ("reads every node's assignment bundle over `sudo -n cat`", `live_managed_dns_validation.rs:284-285`) is accurate about the mechanism, though the stage file's line-288 rejection is the enforcement point regardless.

### 3.2 Operation inventory by portability class

**Trivially portable — the per-OS branch already exists in the binary** (they only need a working transport):

| Operation | Linux | macOS | Windows branch (already written) |
| --- | --- | --- | --- |
| Split-DNS config capture (`:2215-2248`) | `resolvectl status <iface>` | `scutil --dns` | PowerShell `Get-DnsClientServerAddress` rows (`:2235-2246`) |
| Cache flush (`:2254-2298`) | `resolvectl flush-caches` | `dscacheutil -flushcache` | `Clear-DnsClientCache` |
| System-resolver answer (`:2299-2360`) | `resolvectl query` | `dig` + `dscacheutil` | PowerShell `Resolve-DnsName` (`:2339`) |
| Managed-DNS service state (`:2363-2392`) | `systemctl is-active rustynetd-managed-dns.service` | `launchctl print` | `(Get-Service -Name 'RustyNet').Status` (`:2382-2390`) |
| Hosting daemon state (`:2404-2438`) | `systemctl is-active rustynetd.service` | `launchctl print` | same `Get-Service` (`:2426-2436`) |
| Daemon log tail (`:2452-2493`) | `journalctl -u rustynetd.service` | `log show` | `Get-WinEvent -ProviderName 'RustyNet'` (`:2481-2491`) |
| Assignment-bundle path (`:2814-2824`) | `/var/lib/rustynet/rustynetd.assignment` | `/usr/local/var/rustynet/trust/…` | `C:\ProgramData\RustyNet\trust\rustynetd.assignment` |
| Per-node re-push policy (`:678-691`, `:1318-1330`) | re-push | skip | skip (non-Linux) |
| Answer/config parsers | — | `macos_scutil_advertises_managed_zone` `:2534` | `windows_dns_client_lists_loopback_server` `:2556`, `managed_dns_service_active(platform,…)` `:2611` |

**Fundamentally POSIX — needs a real replacement, not a path swap:**

1. **The elevation/transport seam itself** (`sudo -n -k true` probe + `sudo -n <argv>`, §3.1). Windows needs a PowerShell-based execution path — which already exists elsewhere in this repo (§4).
2. **`install(1)` with modes/ownership** — `/etc/rustynet` dir argv (`:52-64`), the dns-zone install block (`:1233-1266`), the traversal install (`:1393-1415`). Coreutils `install` does not exist on Windows; the replacement must map `install -m 0600` semantics onto NTFS ACLs (or accept the daemon's own trust-root ACL model).
3. **`mktemp` + `/tmp` staging** (`:268-270`, scp targets `/tmp/rn-dns-zone.*`, `/tmp/rn-traversal.*` at `:1220-1221`, `:1297`, `:1379-1380`) — replace with a PowerShell temp-path idiom.
4. **Service lifecycle orchestration** — `restart_managed_dns_stack` (`:1466-1532`) and `start_rustynetd_with_reset` (`:1438-1464`) are a systemd choreography: stop/reset-failed/start of `rustynetd-privileged-helper.service`, `rustynetd.service`, `rustynetd-managed-dns.service`, then wait for the daemon socket `/run/rustynet/rustynetd.sock`, then `rustynet state refresh`, then wait for `dns inspect state=valid`. On Windows there is no named managed-DNS unit today (Linux hosts the resolver in a **separate** `rustynetd-managed-dns.service`; per `:775-783` on some platforms the resolver lives inside the main daemon — the Windows shape must be decided: restart `RustyNet` only, and re-derive what "managed resolver active" means from the daemon's own state). The privileged-helper unit has no Windows analog named anywhere in this binary.
5. **`env VAR=… cmd`** prefix (`:1500-1510`, also `:157`) and `sh -lc` PATH resolution — PowerShell `$env:` equivalents.
6. **Signer-side key path** — issuance reads `/etc/rustynet/membership.owner.key` (`:1146`) and installs `/etc/rustynet/dns-zone.pub` on the client. If the signer (exit role) stays Linux — the normal lab topology — zero signer work is needed; only if a Windows node can ever be the signer does that path need `C:\ProgramData\RustyNet\...` treatment. Note the stage as written only fails when *any* node is Windows, and the client role is the one that receives installs.
7. **Daemon-socket wait** — `wait_for_daemon_socket(host, "/run/rustynet/rustynetd.sock", …)` is a POSIX socket path; the Windows equivalent must poll whatever the Windows daemon exposes (named pipe / TCP status), consistent with how other Windows stages already check daemon readiness.

## 4) Windows building blocks that already exist (reuse, do not reinvent)

- **`RemoteShellHost` platform seam — two mature copies.** `crates/rustynet-cli/src/bin/live_lab_bin_support/remote_shell.rs:131` and `crates/rustynet-cli/src/vm_lab/orchestrator/remote_shell.rs:138` both define the trait, and both ship a **`WindowsShellHost` impl driven by `windows_run_powershell` with `powershell_single_quote_escape`** (`bin_support:518+`, `orchestrator:485+`, quoted-script construction at `orchestrator:496-624`), alongside `LinuxShellHost`/`MacosShellHost` and a `MockShellHost` for tests. The `capture_remote_stdout` entry point lives at `crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs:1129`. This is the seam a Windows managed-dns validator should execute through instead of `sudo -n`.
- **The in-binary precedent.** `live_linux_role_switch_matrix_test.rs:156-167` documents the exact split this investigation recommends: "Linux/macOS use the POSIX `sudo -n sh -lc` seam (`capture_root`); Windows uses the `capture_remote_stdout` (`RemoteShellHost`) seam … runnable on a Windows OpenSSH host." The same file shows the repo's fail-closed pattern for unported Linux-shaped preambles (`:773-775`: the Windows blind_exit leg refuses with a SPECIFIC reason rather than improvising).
- **Platform path helpers.** `assignment_bundle_path_for_platform`, `assignment_refresh_env_path_for_platform`, `assignment_watermark_path_for_platform` (imported at `live_linux_role_switch_matrix_test.rs:19-20`) already return Windows paths, e.g. the Windows assignment-refresh env at `C:\ProgramData\RustyNet\config\assignment-refresh.env` (`:42-53`). The binary's own `assignment_bundle_path` (`:2814-2824`) is the same idea, already Windows-complete.
- **Orchestrator adapter precedent for PowerShell probe rendering.** `run_validator` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows.rs:197-223`, per the companion doc) renders probe argv into a PowerShell script and judges JSON output — the pattern a future `dns-zone` status probe on Windows could ride.
- **Daemon-side Windows DNS introspection already exists.** `windows-dns-failclosed-check` collects live `Get-DnsClientServerAddress` + `Get-DnsClientNrptRule` snapshots (`windows_dns_failclosed.rs:440-520`, per the companion doc) — evidence that the daemon, not a shell one-liner, can become the source of "is the managed resolver configured" on Windows if the shell path proves too brittle.

## 5) Scope estimate: **MEDIUM**

Roughly a focused multi-day effort, not an afternoon and not a rewrite:

- **Already done inside the binary** (the expensive part): every probe branch, every parser, the Windows service/log/answer evaluators, the Windows assignment-bundle path constant, the non-Linux re-push skip, and the per-node platform map threaded through from the orchestrator. The evaluation logic (bundle signatures, fail-closed readbacks, DNS answers) is platform-neutral by construction.
- **The real work is the transport + privileged-op seam**: route the `run_root`/`capture_root` family (or add platform-seamed variants) through the existing `RemoteShellHost`/`WindowsShellHost` (§4), convert the `install(1)`/`mktemp`/`env` steps to PowerShell equivalents, map `/etc/rustynet` + `/var/lib/rustynet` + the `/run/rustynet/rustynetd.sock` wait onto the `C:\ProgramData\RustyNet` config/state roots the repo already uses, and decide the Windows service-restart choreography (§3.2 items 1-5, 7).
- **The one genuinely open design question** is item 4 (§3.2): what "restart the managed DNS stack" and "managed resolver service active" mean on Windows, where Linux's separate `rustynetd-managed-dns.service` has no named counterpart — that is a daemon-posture decision, not just scripting, and should be settled against the daemon's own Windows service model before code is written.
- **Cheap wins first**: if the signer stays Linux (usual topology), the issuance side needs nothing; the first runnable milestone is "Windows client passes steps 5-6 and 9 with a PowerShell transport," after which the adversarial restart loop (§2 step 8) is the long tail. The orchestrator-side change is then tiny: replace `reject_unsupported_platforms` (`live_managed_dns_validation.rs:288-304`) with per-node platform dispatch that already exists in the argv (`:273-278`).

Risk note: several Windows branch bodies in the binary carry in-code `REVIEW` markers saying their specifics are inferred (e.g. the event-provider name at `:2446-2451`), and the diagnostic branches are deliberately non-asserting — do not treat their presence as proof any Windows leg has ever executed; this trace found no evidence it has.
