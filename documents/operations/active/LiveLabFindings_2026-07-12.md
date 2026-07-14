# Live Lab Findings — 2026-07-12 (managed_dns green + newly-exposed gaps)

> **RESOLUTION UPDATE (2026-07-12, later same day).** All three findings are
> now dispositioned; live re-verify pending in the next focused run:
>
> - **Finding A — FIXED (option a, skip-if-absent).**
>   `force_local_assignment_refresh` now probes
>   `/etc/rustynet/assignment-refresh.env` first: `test -f` exit 1 (absent) →
>   `CheckResult::Skipped` (the focused lab deliberately does not provision the
>   refresh timer); any other probe failure → `Fail`; transport error → `Err`.
>   A present env file with a failing refresh remains a hard `Fail`. The report
>   writer already excludes skipped checks from the verdict; new regression
>   test `reboot_recovery_report_passes_when_dns_refresh_checks_are_skipped`
>   pins PASS with both refresh checks skipped. Option (b)
>   (provision-the-timer) stays a coverage-enhancement candidate.
> - **Finding B — RESOLVED AS NOT-A-BUG (intent≠reality explained).** The
>   verifying run's own evidence shows bootstrap set the exit's daemon role to
>   **admin** as intended (`bootstrap_node_debian-headless-2.log`:
>   `e2e bootstrap host complete: role=admin`), and `e2e-enforce-host` exports
>   `RUSTYNET_NODE_ROLE` into `install-systemd`'s process env, which takes
>   precedence over preserved unit env — the stale-env-preservation hypothesis
>   was wrong. The observed `RUSTYNET_NODE_ROLE=client` is the **legitimate end
>   state of the role lifecycle**: `role_switch_matrix` and `exit_handoff` both
>   PASSED before the live suite in the verifying run, and the handoff harness
>   leaves the exit demoted to `client`. The `role.rs` Exit→`admin` mapping is
>   the correct **bootstrap intent**; the daemon's fail-closed alignment check
>   then requires the exit's capability set to support every role the lifecycle
>   puts it through — exactly what `a1e49c1`'s canonical admin-owner set
>   (`client,relay_host,exit_server,anchor`) provides. (The `node_id=daemon-local`
>   + `client` unit env observable on the guest between runs is post-cleanup
>   baseline state, not in-run state.)
> - **Finding C — FIXED.** `issue_two_node_traversal_artifacts` (ops_e2e.rs)
>   exit-node metadata aligned to the canonical admin-owner capability set.

Scope: findings from driving `live_managed_dns_validation` to green on the focused
shared-plane Rust `--node` topology (`debian-headless-2:exit` + `debian-headless-4:client`).
Two bugs were fixed and committed (`a1e49c1`); fixing them unmasked a third failure and
surfaced two adjacent observations. This doc records the *remaining* problems so they are not
lost. Every claim below was verified first-hand against the repo and/or the live lab.

Verifying run: report dir `state/managed-dns-verify2-1783854488`, run-matrix row
`livelab-1783855257-798149c2e909` (2026-07-12, `dirty:recorded` — pre-commit). Tally:
31 pass / 1 fail / 26 skip. `live_managed_dns_validation` = **PASS**.

---

## Context — what was fixed and committed (`a1e49c1`)

For provenance (these are DONE, not open):

1. **SSH host-key pin port-suffix.** `SshConnectionParams::new` stores the host as
   `format!("{host}:{port}")` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/node_adapter.rs:84`),
   so orchestrator stages that dispatch standalone e2e binaries build the target
   `debian@192.168.64.4:22`. `LiveLabContext` in
   `crates/rustynet-cli/src/bin/live_lab_support/mod.rs` did not strip the `:22`, breaking the
   pinned-known_hosts lookup candidate, the `ssh -G` resolution, **and** the actual `ssh`/`scp`
   connect (`ssh` cannot resolve the literal hostname `192.168.64.4:22`). Fixed: `target_address`
   strips the port, new `ssh_destination()`/`target_port()` helpers, `ssh`/`scp` use the bare host
   plus `-p`/`-P`, `ssh -G` is fed the bare host, and the known_hosts candidate prefers the explicit
   port. Affects **every** pinned-known_hosts live stage, not just managed-DNS. +7 unit tests.

2. **Exit-role missing `Client` capability.** A regular Linux exit runs the `client` daemon role
   (see Finding B), which requires the `Client` capability, but
   `NodeRole::product_capabilities_for_platform` granted the Linux/Windows Exit role
   `[Anchor, ExitServer, RelayHost]` with no `Client`
   (`crates/rustynet-cli/src/vm_lab/orchestrator/role.rs`). The daemon's
   `validate_auto_tunnel_role_membership_alignment` (`crates/rustynetd/src/daemon.rs:1539`) therefore
   fail-closed the assignment refresh with `assignment target intent lacks required local capability
   client`. Fixed by adding `Client`, matching the canonical admin-owner set
   `client,relay_host,exit_server,anchor` the exit-handoff harness exercises across the
   client→admin lifecycle.

Also fixed a pre-existing test-compile break (`base_config()` missing the `known_hosts_file` field
in `live_linux_managed_dns_test.rs`, orphaned by `4d04af5`).

---

## FINDING A — `live_reboot_recovery_validation` fails on a missing assignment-refresh env file in the focused Rust `--node` topology

**Severity: Medium.** It is now the sole failing stage of the focused run, but it is a lab-setup
gap, not a defect in the reboot-recovery path itself.

### What is true

The reboot core passes. In the verifying run's report the reboot itself is healthy:
`exit_reboot_returns=pass`, `exit_boot_id_changes=pass`, `client_reboot_returns=pass`,
`client_boot_id_changes=pass` (`state/managed-dns-verify2-1783854488/live_reboot_recovery_report.json`).
SSH through the rebooted node works (the Bug-1 fix carries through here too).

The stage fails only on the post-reboot assignment-refresh sub-check. `force_local_assignment_refresh`
(`crates/rustynet-cli/src/bin/live_linux_reboot_recovery_test.rs:463`) runs
`rustynet ops force-local-assignment-refresh-now`, which reads `/etc/rustynet/assignment-refresh.env`:

```
[reboot-recovery] forcing local assignment refresh on debian@192.168.64.4:22
[reboot-recovery] assignment refresh failed on debian@192.168.64.4:22: error [generic_failure (1)]:
  inspect assignment refresh env file failed (/etc/rustynet/assignment-refresh.env):
  No such file or directory (os error 2)
```

The focused Rust `--node` lab setup does not provision the assignment-refresh timer/env file — the
lab distributes a single signed bundle and does not install the refresh timer (see the
`RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400` rationale in
`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_install.rs`, which exists precisely
because the lab does not rotate the assignment bundle). The reboot-recovery test assumes that
infrastructure is present.

This stage only ran now because managed_dns passing unblocked the downstream live stages; it has
**never been green in the Rust `--node` path** (run matrix: a single
`live_reboot_recovery_validation` row, this one).

### Fix options (decision needed)

- **(a) Skip-if-absent (smaller, recommended default).** Make `force_local_assignment_refresh` return
  `CheckResult::Skipped` when the env file / refresh timer is not provisioned, mirroring the existing
  `run_two_hop_subcheck` incomplete-topology skip
  (`live_linux_reboot_recovery_test.rs:493`). Makes the focused run green; slightly reduces coverage
  in this topology (the post-reboot refresh is not exercised).
- **(b) Provision the env/timer (larger, higher coverage).** Wire the assignment-refresh env file
  (and timer) into the focused Rust `--node` setup so the check runs for real. Touches the
  install/adapter path and needs its own live re-verify.

---

## FINDING B — Linux Exit daemon-role intent (`admin`) disagrees with reality (`client`)

**Severity: Low–Medium.** The committed capability fix makes the exit node correct under *either*
role, but intent and reality should be reconciled so the mapping does not mislead.

### What is true

`NodeRole::daemon_node_role_for_platform` maps Linux (and Windows) `Exit` → daemon role **`admin`**
(`crates/rustynet-cli/src/vm_lab/orchestrator/role.rs:119`), and the Linux install passes
`--role admin` for an exit node (`linux_install.rs:209`). But the live exit node
`debian-headless-2` (192.168.64.4) runs with **`RUSTYNET_NODE_ROLE=client`** — verified directly from
its systemd unit environment:

```
Environment=RUSTYNET_NODE_ROLE=client
```

That is exactly why the auto-tunnel validation ran as `NodeRole::Client` (requires the `Client`
capability) and why Finding-Context-2's fix was needed.

### Likely cause + fix direction

`ops install-systemd` resolves the role with
`env_string_or_existing_default("RUSTYNET_NODE_ROLE", "client", &existing_env)`
(`crates/rustynet-cli/src/ops_install_systemd.rs:321`) — it preserves an existing env value and
otherwise defaults to `client`. A node that carried `RUSTYNET_NODE_ROLE=client` from an earlier
install (or an enforce step that never sets `admin` in the unit env) stays `client` even though the
adapter intends `admin`. Two questions to resolve:

1. **Is a regular exit supposed to run daemon-role `admin` or `client`?** The exit here is the
   membership owner/signer, which argues for `admin`; but it also participates as a mesh client,
   and the `client` role + full `client,…,anchor` cap set is what the exit-handoff harness proves.
2. Depending on the answer: either fix the install/enforce path to actually set `RUSTYNET_NODE_ROLE`
   (and defeat the stale-env preservation) so the node runs `admin` as intended, **or** retire/correct
   the `daemon_node_role_for_platform` Exit→`admin` mapping so it matches the `client` reality and
   stops implying an unused configuration.

The capability fix (`a1e49c1`) is safe either way: an `admin`-role daemon requires only `Anchor`
(still present), and a `client`-role daemon requires `Client` (now present).

---

## FINDING C — Latent client-less exit spec in `ops_e2e.rs`

**Severity: Low (latent).** Not in the managed_dns path, but the same class of bug as the one just
fixed in `role.rs`.

`issue_two_node_traversal_artifacts` registers the exit node with
`capabilities: vec![RoleCapability::Anchor, RoleCapability::ExitServer]`
(`crates/rustynet-cli/src/ops_e2e.rs:3365`) — no `Client`, no `RelayHost`. Any path that issues an
exit **assignment** bundle from this node metadata would fail the `client`-role auto-tunnel validation
the same way managed_dns did. This helper feeds *traversal*-artifact issuance
(`execute_ops_e2e_issue_traversal_bundles_from_env` uses `issue_traversal_bundle_artifacts`, which does
not touch the assignment bundle), so it did not cause the managed_dns failure — but it is inconsistent
with the canonical admin-owner set `client,relay_host,exit_server,anchor` and should be aligned if it
is ever used to issue an exit assignment. Verify first whether any live path issues an exit assignment
from this metadata.

---

## Cross-cutting note

Findings B and C are two more instances of the same root theme the `role.rs` fix addressed: **the exit
role's capability/daemon-role configuration is defined in several places that do not agree, and only
the daemon's fail-closed policy check surfaces the disagreement.** A single typed authority for
per-role (daemon-role, capability-set) pairs — consumed by the adapters, the install path, and the
e2e helpers — would make this class of drift structurally impossible rather than fixed-once. This is
the same lesson as FINDING 1 of [LiveLabFindings_2026-07-03.md](./LiveLabFindings_2026-07-03.md) (one
registry instead of hand-copied vocabulary), applied to role/capability data.

## FINDING (2026-07-14) — First Ubuntu 26.04 `--node` run: engine works; three onboarding gaps; a network-tooling gap

**Ubuntu 26.04 LTS (aarch64) is now `--node`-proven for the node lifecycle.** A single-node run
(`ubuntu-utm-1:exit`, report dir `state/ubuntu-node-1784034920`) passed `preflight`, `cleanup_hosts`,
**`bootstrap_hosts`** (deploy + build + install rustynet on Ubuntu through the engine), `collect_pubkeys`,
and `membership_init` (9 pass / 1 fail / 48 skip; matrix row appended). It failed only at
`distribute_assignments` with `assignment env file key ALLOW_SPEC must not be empty` — a **degenerate
single-node artifact** (a lone node has no peer pairs → empty ACL allow-spec → default-deny fail-closes
correctly), NOT an Ubuntu incompatibility. Separately, `rustynetd` compiles cleanly on both Ubuntu 26.04
and Rocky 10.2 aarch64 (manual `cargo build`, same day). Distro matrix now: Debian (deep reference),
Rocky 10.2 (`active_exit` + traffic live-proven 2026-07-10), Ubuntu 26.04 (bootstrap/lifecycle proven
2026-07-14), Fedora 44 (compile-ready, never run).

**Three onboarding gaps had to be closed by hand before preflight passed — each is something a proper
enrollment / the uniform tooling should own:**
1. Host key not pinned in `known_hosts_lab` (bridged node, new IP) → the strict-checked OS-version probe
   failed with an umbrella `linux` non-attribution. Fixed via `ssh-keyscan`.
2. No passwordless sudo → preflight's clock probe died on `sudo: interactive authentication is required`.
   `prime_remote_access` primes sudo, but `preflight` runs first — chicken-and-egg. Set NOPASSWD to match
   the debian/rocky lab posture.
3. Clock skew ~4.9 days → RNQ-21 correctly fail-closed (>90s tolerance). Force-synced to host time.

**TOOLING GAP — `vm-lab-network-prepare` validates attachment MODE, not L2/subnet reachability.**
`ubuntu-utm-1` and `debian-headless-2` have **byte-identical UTM Network configs** (`Mode=Shared`,
`Hardware=virtio-net-pci`, `IsolateFromHost=false`; only the MAC differs), yet macOS `vmnet` placed
debian on the shared `.64` plane (gateway `192.168.64.1`) and ubuntu on the **host's real LAN**
(`10.230.76.x`; host en0 = `10.230.76.56`). ubuntu cannot reach `192.168.64.4`/`.1`, so a 2-node mesh
cannot form. But `vm-lab-network-prepare --profile mgmt_shared_smoke_v1 --vm ubuntu-utm-1` reports
`current=[nic0=shared] … already compliant; no change` — it green-lights a node that is mode-`Shared`
but on a non-meshable subnet, and a reboot does not re-lease it onto the vmnet. **Recommendation:** the
audit/prepare path should verify the *observed subnet / gateway reachability against the rest of the
fleet*, not just the attachment-mode string, and flag (or repair) a same-mode-wrong-L2 node. The actual
fix is UTM-attachment-level (recreate/re-toggle the NIC in the UTM app).

**RESOLVED (tooling, 2026-07-14).** `detect_offfleet_subnet_findings` (network_audit.rs) now derives the
fleet's consensus management plane (the modal `network_group` CIDR across the inventory, requiring ≥2
nodes) and emits an `off_fleet_subnet` **Error** for any reachable guest whose *live observed* underlay
IPv4 is not on that plane — with a repair hint (regenerate MAC / re-create NIC; a mode rewrite alone
won't move it). It runs on both `vm-lab-network-audit` and `vm-lab-network-preflight` (via
`run_network_observation`), and `vm-lab-network-prepare`'s dry-run gained a footer clarifying it rewrites
attachment **mode only**, not L2/subnet, and points to the audit. 4 unit tests incl. the negative (mode
`Shared` + observed subnet ≠ fleet plane ⇒ Error, not compliant). Fail-safe: no fleet consensus ⇒
nothing flagged.
