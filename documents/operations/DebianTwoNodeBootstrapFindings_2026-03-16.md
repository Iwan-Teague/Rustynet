# Debian Two-Node Bootstrap Findings (2026-03-16)

## Scope
- exit host: `debian@192.168.64.22`
- client host: `debian@192.168.64.24`
- test path: `rustynet-cli ops run-debian-two-node-e2e`

## Repo-side defects fixed
1. SSH control socket path was too long on macOS.
- File: `crates/rustynet-cli/src/ops_e2e.rs`
- Fix: shortened the temporary workspace path and SSH control-path directory.

2. Remote sudo command construction was invalid over SSH.
- File: `crates/rustynet-cli/src/ops_e2e.rs`
- Fix: replaced empty `sudo -p ""` prompt handling with a non-empty fixed prompt.

3. Remote bootstrap path was circular.
- File: `crates/rustynet-cli/src/ops_e2e.rs`
- Previous behavior: tried to run `cargo` remotely before the remote host had a toolchain bootstrap path.
- Fix: added a generated Debian remote bootstrap script that installs prerequisites, bootstraps Rust, builds, installs binaries, and then hands off to the existing host bootstrap operation.

4. Remote bootstrap trust refresh depended on a missing system group.
- File: `crates/rustynet-cli/src/ops_e2e.rs`
- Fix: remote bootstrap script now precreates the `rustynetd` system group before invoking the committed `e2e-bootstrap-host` path.

5. Remote resolver health checks could hang.
- File: `crates/rustynet-cli/src/ops_e2e.rs`
- Fix: bounded DNS health checks with `timeout` so the bootstrap fails clearly instead of wedging.

6. Debian resolver package side effects broke NSS lookup order.
- File: `crates/rustynet-cli/src/ops_e2e.rs`
- Fixes:
  - removed `systemd-resolved` and `libnss-resolve` from the two-node Debian prerequisite list
  - added bootstrap repair of `/etc/nsswitch.conf` back to `hosts: files dns`

## Current blocker
Host `192.168.64.22` still cannot resolve DNS during fresh bootstrap.

Observed facts:
- plain SSH to `.22` works
- IPv4 address and default route are present on `.22`
- the VM previously reached raw IPs (for example `1.1.1.1`)
- DNS resolution fails even after rewriting `/etc/resolv.conf`
- bootstrap now fails cleanly with:
  - `DNS repair failed for static.rust-lang.org via resolvers: 192.168.64.1 1.1.1.1 8.8.8.8`

Interpretation:
- this is no longer a hidden Rustynet CLI/bootstrap hang
- it is an explicit VM/underlay DNS failure on `.22`
- until `.22` can resolve package/toolchain hosts, the clean-install two-node path cannot complete honestly

## Commands used for validation
```bash
cargo test -p rustynet-cli ops_e2e -- --nocapture
cargo build -p rustynet-cli
./target/debug/rustynet-cli ops run-debian-two-node-e2e \
  --exit-host 192.168.64.22 \
  --client-host 192.168.64.24 \
  --ssh-user debian \
  --ssh-identity /tmp/rustynet_debian64_ed25519 \
  --ssh-known-hosts-file /tmp/debian64_known_hosts \
  --sudo-password-file /tmp/debian64_sudo.pass \
  --ssh-allow-cidrs 192.168.64.0/24 \
  --report-path artifacts/operations/debian64_two_node_e2e_report.json
```

## Next step
Repair DNS on `192.168.64.22` at the VM/guest networking layer, then rerun the same two-node E2E path.

## Additional blocker discovered after DNS repair
The run later reached remote exit-node route advertisement and failed on the daemon socket validator.

Observed failure on `debian@192.168.64.22`:
```text
error: daemon unreachable: daemon socket parent directory has insecure permissions: mode 770
```

Context:
- `/run/rustynet` is created as `root:rustynetd 770`
- `/run/rustynet/rustynetd.sock` is `rustynetd:rustynetd 600`
- this is a legitimate root-managed shared runtime layout
- the CLI currently validates daemon sockets with the stricter owner-only policy instead of the shared-runtime policy

Consequence:
- remote commands such as `rustynet route advertise 0.0.0.0/0` fail even though the daemon is running

Current local fix in progress:
- [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs) now routes `/run/rustynet` daemon sockets through `validate_root_managed_shared_runtime_socket(...)`
- that fix is local in the workspace; the remote two-node runner still builds from the committed archive SHA printed at runtime unless the source packaging path is changed or the fix is committed first

## Additional blocker discovered after committing the socket fix
The rerun moved past socket validation and failed closed in daemon runtime policy.

Observed failure on `debian@192.168.64.22`:
```text
error: daemon is in restricted-safe mode
```

`rustynet status` on the exit host showed:
```text
bootstrap_error=reconcile failure threshold exceeded: 90
last_reconcile_error=traversal authority rejected reconcile apply: traversal authority requires signed traversal state for all managed peers
restricted_safe_mode=true
restriction_mode=Permanent
```

Interpretation:
- the two-node E2E path was still only provisioning signed assignment bundles
- `rustynetd` now enforces signed traversal authority for all managed peers in auto-tunnel mode
- the Debian two-node bootstrap path therefore started the daemon without the required traversal verifier and traversal bundle
- the daemon failed closed exactly as designed

Repo-side fix:
- File: [crates/rustynet-cli/src/ops_e2e.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_e2e.rs)
- Changes:
  - `e2e-issue-assignments` now also issues signed per-host traversal bundles and a traversal verifier key from the same control-plane secret
  - `run-debian-two-node-e2e` now installs `/etc/rustynet/traversal.pub` and `/var/lib/rustynet/rustynetd.traversal` on both hosts before the enforced daemon start
  - the traversal watermark is cleared on install so reruns cannot be poisoned by stale traversal state

Security effect:
- no fallback or disablement of traversal authority was introduced
- the E2E path now satisfies the same signed-state contract the daemon already requires
- the daemon continues to fail closed if the traversal state is missing or invalid

## Additional blocker discovered after traversal provisioning
The next rerun progressed into traversal-authoritative reconcile and exposed a privileged-helper allowlist mismatch.

Observed daemon error on both hosts:
```text
traversal authority failed to read handshake evidence for peer <peer>: backend error: Internal: privileged helper wg invocation failed: unsupported wg argument schema
```

Why it broke:
- the traversal runtime now reads WireGuard handshake freshness through:
  - `wg show <interface> latest-handshakes`
- the backend already emits that command
- the privileged helper allowlist still rejected that `wg` argument schema

Repo-side fix:
- File: [crates/rustynetd/src/privileged_helper.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/privileged_helper.rs)
- Changes:
  - allowed `wg show <interface> latest-handshakes`
  - added a focused regression test for that accepted schema

Security effect:
- this does not broaden `wg` access generally
- it adds one specific read-only schema already required by the backend
- all other unsupported `wg` invocations remain rejected
