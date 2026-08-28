# macOS Path-Constant Audit — sibling sweep of the QH-40 `DEFAULT_STATE_PATH` fix

- **Date:** 2026-08-28
- **Verified against:** commit `c00960a3` on worktree branch `ai-edit/edit-1787925733552-56044-9` (branched from `main` HEAD); tree clean except this document and its index entry.
- **Trigger:** QH-40 (commit `8f9e7f5a`, "Fix macOS shutdown-residue-check fail-open state-path default", recorded in [MacCellsHarvest_2026-08-28.md](./MacCellsHarvest_2026-08-28.md) §3.4) found that `DEFAULT_STATE_PATH`'s `#[cfg(not(windows))]` arm silently inherited the Linux path on macOS, so a fail-closed residue check failed open. This audit enumerates **every other path constant in `crates/rustynetd/src/daemon.rs` with the same latent shape** and, for each, determines whether the wrong-on-macOS default can actually bite.
- **Scope note:** audit only — **no production code was changed**. Per-constant fix shapes are stated for follow-up; none has been applied. Line numbers below are against `c00960a3`.

## Method

1. Enumerated all `DEFAULT_*` path constants in `crates/rustynetd/src/daemon.rs` and their `#[cfg]` arms (grep + read of lines 160–470).
2. Read the macOS deployment path end-to-end: `scripts/bootstrap/macos/Install-RustyNetMacosService.sh` (daemon launchd plist, helper plist) and `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh` (key material provisioning), plus the launchd plist rendering in `crates/rustynet-cli/src/main.rs` (`macos_runtime_service_context_from_env`).
3. For each constant, grepped the workspace for every consumer (`rustynetd`, `rustynet-cli`, `rustynet-cli/src/bin/*`, `ops_install_systemd.rs`), classified the consuming function (deploy-time override / CLI arg default / doctor / cosmetic / test), and judged the direction of a wrong-on-macOS default (fails open / fails closed / inert).

## Reference: the installer's macOS roots

The macOS service installer (`Install-RustyNetMacosService.sh`) deploys under:

| Root | Value | Set at |
| --- | --- | --- |
| `STATE_ROOT` | `/usr/local/var/rustynet` | :31 |
| `SOCKET_PATH` | `/private/var/run/rustynet/rustynetd.sock` | :34 |
| `PRIVILEGED_HELPER_SOCKET` | `/private/var/run/rustynet/rustynetd-privileged.sock` | :35 |

The daemon plist **passes explicit flags** for every path the daemon actually opens at runtime: `--state` (:423-424), `--trust-evidence`/`--trust-verifier-key`/`--trust-watermark` (:425-430, under `${STATE_ROOT}/trust/`), `--membership-snapshot`/`--membership-log`/`--membership-watermark` (:436-441, under `${STATE_ROOT}/membership/`), `--gossip-watermark` (:404-405, :442), `--auto-tunnel-bundle`/`-verifier-key`/`-watermark` (:445-450, `trust/`), `--traversal-bundle`/`-verifier-key`/`-watermark` (:452-457, `trust/`), `--dns-zone-bundle`/`-verifier-key`/`-watermark` (:460-465, `trust/`), `--wg-private-key /private/var/run/rustynet/wireguard.key` (:467-475), `--wg-encrypted-private-key` + `--wg-key-passphrase` **conditionally** when the files exist (:299-319; `${STATE_ROOT}/keys/wireguard.key.enc`, `${STATE_ROOT}/bootstrap/wireguard.passphrase`), `--wg-public-key ${STATE_ROOT}/keys/wireguard.pub` (:477-478), `--socket` (:483-484), `--privileged-helper-socket` (:485-486). The helper plist passes `--socket ${PRIVILEGED_HELPER_SOCKET}` (:569-570). The script carries an intentionally-omitted-flag audit table at :346-399 documenting each deliberate omission.

`Bootstrap-RustyNetMacos.sh` provisions key material with explicit outputs: `key init` passes all four WireGuard custody paths (`--runtime-private-key`/`--encrypted-private-key`/`--public-key`/`--passphrase-file --force`, :1057-1061); `trust keygen`/`trust issue` pass explicit outputs (:1155-1170). So the *writer* side never relies on a default on macOS either.

**Not passed by the plist (and therefore default-resolved if ever consumed):** `membership-owner-signing-key` (no such flag exists in the plist), relay-fleet bundle/watermark (no flag, no env), `anchor-bundle-pull-token` (comment at :379 documents that the default `None` matches the systemd unit), and `--wg-encrypted-private-key`/`--wg-key-passphrase` when those files do not yet exist.

## Per-constant verdicts

Two constants already carry macOS arms and are **correct**: `DEFAULT_SOCKET_PATH` (`daemon.rs:163-164`, macOS `/private/var/run/rustynet/rustynetd.sock` — matches installer `SOCKET_PATH`) and `DEFAULT_STATE_PATH` (`daemon.rs:176-177`, macOS `/usr/local/var/rustynet/rustynetd.state`, the QH-40 fix; both defaults resolve through the shared `default_state_path()` at `daemon.rs:192-194` so writer and checker cannot drift). Everything else is `#[cfg(not(windows))]` with the Linux value macOS inherits.

### Latent-but-inert (deploy-time override makes the default unreachable in the deployed configuration)

| Constant | daemon.rs | macOS-inherited value | Deployed-to instead (plist flag) |
| --- | --- | --- | --- |
| `DEFAULT_TRUST_EVIDENCE_PATH` | :196 | `/var/lib/rustynet/rustynetd.trust` | `${STATE_ROOT}/trust/…` (:425-430) |
| `DEFAULT_TRUST_VERIFIER_KEY_PATH` | :200 | `/etc/rustynet/trust-evidence.pub` | `${STATE_ROOT}/trust/…` (:425-430) |
| `DEFAULT_TRUST_WATERMARK_PATH` | :204 | `/var/lib/rustynet/rustynetd.trust.watermark` | `${STATE_ROOT}/trust/…` (:425-430) |
| `DEFAULT_MEMBERSHIP_SNAPSHOT_PATH` | :208 | `/var/lib/rustynet/membership.snapshot` | `${STATE_ROOT}/membership/…` (:436-441) |
| `DEFAULT_MEMBERSHIP_LOG_PATH` | :212 | `/var/lib/rustynet/membership.log` | `${STATE_ROOT}/membership/…` (:436-441) |
| `DEFAULT_MEMBERSHIP_WATERMARK_PATH` | :271 | `/var/lib/rustynet/membership.watermark` | `${STATE_ROOT}/membership/…` (:436-441) |
| `DEFAULT_AUTO_TUNNEL_BUNDLE_PATH` | :280 | `/var/lib/rustynet/rustynetd.assignment` | `${STATE_ROOT}/trust/…` (:445-450) |
| `DEFAULT_AUTO_TUNNEL_VERIFIER_KEY_PATH` | :284 | `/etc/rustynet/assignment.pub` | `${STATE_ROOT}/trust/…` (:445-450) |
| `DEFAULT_AUTO_TUNNEL_WATERMARK_PATH` | :289-290 | `/var/lib/rustynet/…watermark` | `${STATE_ROOT}/trust/…` (:445-450) |
| `DEFAULT_TRAVERSAL_BUNDLE_PATH` | :300 | `/var/lib/rustynet/rustynetd.traversal` | `${STATE_ROOT}/trust/…` (:452-457) |
| `DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH` | :308 | `/etc/rustynet/traversal.pub` | `${STATE_ROOT}/trust/…` (:452-457) |
| `DEFAULT_TRAVERSAL_WATERMARK_PATH` | :312-313 | `/var/lib/rustynet/…watermark` | `${STATE_ROOT}/trust/…` (:452-457) |
| `DEFAULT_DNS_ZONE_BUNDLE_PATH` | :357 | `/var/lib/rustynet/rustynetd.dns-zone` | `${STATE_ROOT}/trust/…` (:460-465) |
| `DEFAULT_DNS_ZONE_VERIFIER_KEY_PATH` | :361 | `/etc/rustynet/dns-zone.pub` | `${STATE_ROOT}/trust/…` (:460-465) |
| `DEFAULT_DNS_ZONE_WATERMARK_PATH` | :365 | `/var/lib/rustynet/…watermark` | `${STATE_ROOT}/trust/…` (:460-465) |
| `DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH` | :390 | `/run/rustynet/wireguard.key` | `/private/var/run/rustynet/wireguard.key` (:467-475) |
| `DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH` | :394 | `/var/lib/rustynet/keys/wireguard.key.enc` | `${STATE_ROOT}/keys/…` (:299-319, :477-478) |
| `DEFAULT_WG_KEY_PASSPHRASE_PATH` | :399 | `/var/lib/rustynet/keys/wireguard.passphrase` | `${STATE_ROOT}/bootstrap/…` (:299-319) |
| `DEFAULT_WG_PUBLIC_KEY_PATH` | :403 | `/var/lib/rustynet/keys/wireguard.pub` | `${STATE_ROOT}/keys/…` (:477-478) |
| `DEFAULT_RELAY_FLEET_BUNDLE_PATH` | :304 | `/var/lib/rustynet/rustynetd.relay-fleet` | *(no plist flag — see below)* |
| `DEFAULT_RELAY_FLEET_WATERMARK_PATH` | :317-318 | `/var/lib/rustynet/…watermark` | *(no plist flag — see below)* |

`DaemonConfig::default` (`daemon.rs:2218-2289`) wires these constants into the runtime config, and the launchd plist overrides every one the daemon opens — verified flag-by-flag above. The bootstrap scripts write key material to the *same* installer paths explicitly, so the writer/reader pair is consistent on macOS regardless of the constants.

**Relay-fleet special case (still classified latent, with a caveat):** the macOS plist passes **no** relay-fleet flag and sets no `RUSTYNET_RELAY_FLEET_*` env, so on a deployed macOS daemon these defaults *would* be live. But the only consumer, `load_optional_relay_fleet` (`daemon.rs:4655-4685`), treats a missing fleet file as `Ok(None)` (:4662-4664) — the relay-fleet feature silently stays dormant; and when a bundle *does* exist the watermark is mandatory (:4665-4669). No trust bypass is possible via the wrong path (a file at `/var/lib/rustynet/` cannot exist on macOS under normal deployment, and if one were planted it would still have to verify against its watermark). Direction: fail-closed-by-absence, operationally silent. This is the closest cousin to a real risk in the set and should be revisited **when macOS relay cells come online** (the Parity Refresh has no macOS relay proven yet).

**`DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH` (:275, `/etc/rustynet/membership.owner.key`)** — not part of `DaemonConfig`; consumed CLI-side only (`main.rs` `run_membership_init` :4210-4227; `rustynet-cli/src/main.rs:13795`). On macOS the deployed key lives at `${STATE_ROOT}/membership/` per the harvest doc; the bare default is wrong on macOS. Every real invocation passes `--owner-key` explicitly (bootstrap `trust keygen` :1155-1170), and the failure direction is fail-closed (missing file → command errors). Latent-but-inert.

**`DEFAULT_ANCHOR_BUNDLE_PULL_TOKEN_PATH` (:216-217)** — the only constant in the file with **no `#[cfg]` at all** (all platforms share one value). It has **zero consumers outside daemon.rs**; the daemon resolves the pull-token path env-only as `Option` (`daemon.rs:2238-2239`, default `None` = no token enforced), and the installer comment at `Install-RustyNetMacosService.sh:379` documents that `None` matches the systemd unit. The constant is dead/legacy. **Correct (inert)** — though a follow-up could simply delete it.

**`DEFAULT_TRUSTED_HELPER_SOCKET_PATH` (:464)** — a re-export of `DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH` (`privileged_helper.rs:61`, `#[cfg(not(windows))]` → `/run/rustynet/rustynetd-privileged.sock`; windows arm :63). The macOS helper plist passes `--socket /private/var/run/rustynet/rustynetd-privileged.sock` (:569-570) explicitly, so the deployed helper never uses the default. Latent-but-inert in the deployed configuration; the bare default is wrong on macOS.

### Consumer-side constants that are wrong on macOS but fail closed (no fail-open found)

These are bare-default resolutions reachable on macOS **outside** the deployed daemon, each checked for direction:

- **`rustynet-cli` duplicate constants** — `crates/rustynet-cli/src/main.rs` defines its *own* copies with no macOS arms: `DEFAULT_DAEMON_SOCKET_PATH` (cli:10828, `/run/rustynet/rustynetd.sock`) and `DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH` (cli:10842, `/run/rustynet/rustynetd-privileged.sock`). These **diverge from daemon.rs's macOS-correct `DEFAULT_SOCKET_PATH`** (`/private/var/run/…`). Consumed by `macos_runtime_service_context_from_env` (cli:12539-12576, resolving `RUSTYNET_SOCKET` :12558 and `RUSTYNET_PRIVILEGED_HELPER_SOCKET` :12559-12562) for macOS launchd runtime operations. Wrong on macOS by default; env-overridable; every mis-resolution lands on a nonexistent socket → connect error, i.e. **fails closed**. Also consumed by `execute_ops_init_membership` (:13763, snapshot :13786/log :13788/watermark :13791/owner-key :13795, watermark+owner-key from cli dup consts :10820-10821), `force_local_assignment_refresh_now_ops` (:14600 → :14631-14635, dup consts cli:10826-10827), `signing_passphrase_ops_config_from_env` (:14756 → :14778), `wireguard_custody_ops_config_from_env` (:14799 → :14817-14826), `membership_paths` (:16850-16859) — all missing-file → error, fail closed.
- **`anchor pull-bundle` watermark default** — `parse_anchor_command` (cli:6129) defaults `--watermark-path` to `DEFAULT_MEMBERSHIP_WATERMARK_PATH` (cli:6181-6184). Wrong file on macOS; attestation verification fails closed on the missing/wrong file.
- **`execute_ops_ensure_local_trust_material`** uses `DEFAULT_TRUST_VERIFIER_KEY_PATH` (cli:12763 → :12785) and **`execute_doctor`** (cli:17159 → trust verifier :17194): wrong path on macOS → missing-file error / check reports absent. Fail-closed direction.
- **`check_macos_doctor`** (cli:17302) checks `DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH` + `DEFAULT_WG_KEY_PASSPHRASE_PATH` (cli:17322-17332): it only appends a "✓ present" line when the file exists and has **no failure branch** (the `_all_pass` accumulator is unused in the macOS function), so on macOS — where those Linux-path files never exist — the check silently vanishes rather than false-passing. Wrong-path files can never produce a "✓ present" on macOS, so there is **no false-green**: benign direction, but the custody check is dead code on macOS. (The function's plist checks at :17304-17319 and keychain checks :17334-17348 do work.)
- **`check_linux_doctor`** (cli:17216 → :17229-17230) — Linux-only by construction.
- **`membership_incident_drill`** (`crates/rustynet-cli/src/bin/membership_incident_drill.rs:10-11`) carries its own copies of the membership snapshot/log defaults, resolved env-overridably (:48-55) and passed as args to `rustynet membership generate-evidence` (:61), which fails closed on missing artifacts (drill `verify_artifacts` :115-188 → `PolicyReject`).
- **`ops_install_systemd.rs:351-361`** uses the dns-zone defaults — the **Linux** systemd installer; out of macOS scope by design.
- **`rustynetd/src/main.rs` arg defaults** — `run_key_init_gossip` (:603, :691-693 passphrase), `run_key_init` (:2859-2863, all four WG paths), `run_key_migrate` (:2926-2931), `run_membership_add_peer` (:3958-3979 snapshot/log), `run_membership_init` (:4210-4227 snapshot/log/watermark/owner-key): interactive/ops subcommands defaulting to Linux paths on macOS; every real macOS provisioning flow (Bootstrap script) passes explicit flags, and a bare invocation errors on the missing file. Fail-closed.
- **Cosmetic/test consumers** — help & status text (rustynetd main.rs:4691-4747; cli `execute_config_show` :17515 → :17524-17548); tests `parse_daemon_config_defaults_dns_zone_settings` (rustynetd main.rs:6505, defaults :6509-6517), `membership_init_pub_key_path_matches_membership_owner_key_path` (:6701, :6704-6705), `parse_supports_anchor_commands` (cli:23704, :23768).

## Headline verdict

**No constant reproduces the QH-40 §3.4 fail-open.** QH-40 was dangerous because a *fail-closed checker* resolved a default and reported "clean" on a residue-carrying host. Every wrong-on-macOS default found here resolves in one of four benign directions: (a) overridden at deploy time by an explicit plist/bootstrap flag; (b) consumed by an ops/CLI path that **fails closed** on the missing file; (c) cosmetic or test-only; (d) a doctor check that silently omits itself rather than false-passing. The closest latent risk is the **relay-fleet pair** (no macOS plist flag, `Ok(None)` silent dormancy) — inert today because no macOS relay cell is deployed, but the exact spot to re-audit when the macOS relay role goes live.

## Follow-up fix shapes (NOT applied — audit only)

Status 2026-08-28 (worktree branch `ai-edit/edit-1787926341142-56044-10`): shapes **#2, #3, and #5 are applied and gate-verified** (`cargo fmt --all -- --check`, `cargo clippy -p rustynet-cli -p rustynetd --all-features --locked -- -D warnings`, targeted `cargo test -p rustynet-cli --bin rustynet-cli tests::macos` / `-p rustynetd --lib shutdown_residue`). Shapes #1 and #4 remain open as scoped below.

1. **Daemon constants (the 21 latent-but-inert rows):** mirror the QH-40 pattern — either add `#[cfg(target_os = "macos")]` arms at the installer roots (`/usr/local/var/rustynet/…`, `/private/var/run/…`, `/etc` → `${STATE_ROOT}/trust` equivalents) or, preferred for drift-resistance, introduce shared `default_*_path()` resolver functions like `default_state_path()` (`daemon.rs:192-194`) so every consumer resolves one function rather than a constant. *(APPLIED where the CLI sockets were concerned via #2; the daemon-side macOS arms themselves remain open.)*
2. **CLI duplicate constants (cli:10820-10828, :10842):** ✅ **DONE 2026-08-28.** The `rustynet-cli`-local copies `DEFAULT_DAEMON_SOCKET_PATH` and `DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH` are deleted; all consumers (including `macos_runtime_service_context_from_env`) now resolve `rustynetd::daemon::DEFAULT_SOCKET_PATH` (macOS-armed to `/private/var/run/rustynet/rustynetd.sock`) and `rustynetd::privileged_helper::DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH`. Env overrides (`RUSTYNET_SOCKET`, `RUSTYNET_PRIVILEGED_HELPER_SOCKET`) are untouched. Pinned by `#[cfg(target_os = "macos")]` tests `macos_cli_daemon_socket_default_is_rustynetd_installer_path` / `macos_cli_helper_socket_default_is_rustynetd_constant`. Note: the helper constant itself still carries only the Linux value on macOS (`/run/...`) — fixing that is daemon-side shape-#1 work, out of scope here; the deployed helper socket is passed explicitly by the helper plist.
3. **`check_macos_doctor` WG custody check (cli:17322-17332):** ✅ **DONE 2026-08-28** — pointed at the real macOS custody paths (`/usr/local/var/rustynet/keys/wireguard.key.enc`, `/usr/local/var/rustynet/bootstrap/wireguard.passphrase`, i.e. installer `STATE_ROOT`) and absence is now a loud `✗ key file missing: …` failure line that flips the `_all_pass` accumulator (matching `check_linux_doctor`'s failure mechanism), instead of the old Linux-path probe that silently vanished on macOS. Report-line contract extracted into `macos_custody_file_check_line` and unit-tested (`macos_doctor_custody_paths_are_installer_roots_not_linux_defaults`, `macos_doctor_custody_line_fails_loudly_when_absent`).
4. **Relay-fleet on macOS (pre-work for the relay parity cell):** when the macOS relay role is elected, add `--relay-fleet-bundle`/`--relay-fleet-watermark` (or env) to `Install-RustyNetMacosService.sh` and give the constants macOS arms; until then consider a startup warning when `load_optional_relay_fleet` returns `Ok(None)` on a relay-role node.
5. **`DEFAULT_ANCHOR_BUNDLE_PULL_TOKEN_PATH` (:216-217):** ✅ **DONE 2026-08-28** — deleted; a repo-wide re-grep immediately before the edit confirmed zero consumers, and `MAX_ANCHOR_BUNDLE_PULL_TOKEN_BYTES` (live, env-only pull-token path resolution) is untouched.

## Verification status

Docs-only change (this document + its [README.md](./README.md) index entry). No production code touched, so the cargo gates are not triggered by this change; line-number citations were read directly against the `c00960a3` tree during the audit. The 2026-08-28 follow-up commit that applied shapes #2/#3/#5 (see above) is a code change and carries its own gate evidence in the follow-up status note.
