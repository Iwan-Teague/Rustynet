# Audit Checklist

Use this checklist after choosing attack families. The goal is to find the exact code path that would allow a staged attack to succeed or to prove the control is enforced.

## Review Order

1. security requirements and architecture docs
2. artifact issuance and verification
3. privileged boundaries
4. runtime reconciliation and fail-closed behavior
5. orchestration and automation harnesses
6. tests and gates

## Control-Plane Integrity

Check:
- every mutation path requires signed, verified, current control state
- replay and rollback protection uses monotonic or digest-bound state
- stale artifact rejection is explicit
- missing verifier keys fail closed

Search patterns:
- `watermark`
- `max_age`
- `expires_at`
- `nonce`
- `verify`
- `signature`
- `allow`
- `generation`
- `epoch`

## Fallback And Legacy Path Detection

Treat these as immediate review hotspots:
- `fallback`
- `legacy`
- `compat`
- `best-effort`
- `accept-new`
- `TODO`
- `FIXME`
- `|| true`

Questions:
- is there more than one path for a security-sensitive workflow?
- does any path bypass signed state?
- does any shell wrapper continue after a failed security step?

## Local Trust Surface Validation

Check:
- Unix socket paths are absolute
- sockets and parent directories are not symlinks
- permissions are strict and ownership is trusted
- helper clients verify the target path before connecting

Search patterns:
- `UnixStream`
- `metadata`
- `symlink_metadata`
- `PermissionsExt`
- `peer_cred`
- `socket`

## Privileged Helper Boundaries

Check:
- argv-only exec, no shell construction
- strict request schema validation
- bounded argument counts and byte sizes
- no untrusted path execution

Search patterns:
- `Command::new`
- `sh -c`
- `bash -c`
- `system(`
- `exec`
- `helper`
- `schema`
- `validate`

## DNS Integrity

Check:
- only signed DNS bundles are trusted
- records are cross-checked against assignment state
- resolver is loopback-only unless there is a documented secure reason otherwise
- non-managed names are refused by the authoritative path
- there is no `/etc/hosts` fallback

Search patterns:
- `dns`
- `resolver`
- `zone`
- `SERVFAIL`
- `REFUSED`
- `hosts`
- `resolvectl`

## Routing And Exit Selection

Check:
- exit-node and route changes require current signed state
- default-route or egress-interface detection is validated, not assumed
- split-tunnel or bypass routes are scoped and auditable
- selection restore paths are as hardened as selection paths

Search patterns:
- `route`
- `exit`
- `egress`
- `interface`
- `advertise`
- `bypass`

## NAT Traversal And Relay

Check:
- direct/relay promotion requires fresh evidence
- stale traversal bundles are rejected
- reprobe and failback decisions use live state, not only cached decisions
- relay activation is explicit and bounded

Search patterns:
- `traversal`
- `relay`
- `probe`
- `handshake`
- `latest-handshakes`
- `freshness`

## Secret Custody

Check:
- no plaintext secret logging
- temp files are owner-only and scrubbed
- credential injection paths are OS-protected where possible
- secrets do not persist longer than required

Search patterns:
- `passphrase`
- `credential`
- `keychain`
- `systemd-creds`
- `temp`
- `NamedTempFile`
- `debug!`
- `trace!`

## Test And Gate Coverage

Every security control should have at least one verification path:
- unit or integration test
- negative test
- CI gate
- live lab evidence if runtime-specific

Questions:
- if this control broke, what test would fail?
- is there a test for both the good path and the tampered path?
- does the gate validate portable, commit-bound evidence?

## Report Discipline

For every finding, capture:
- title
- severity
- attack family
- exact evidence
- exact file and line or subsystem
- secure expected behavior
- actual behavior
- exact remediation
- required regression test or gate
