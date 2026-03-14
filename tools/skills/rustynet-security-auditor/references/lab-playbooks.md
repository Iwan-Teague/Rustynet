# Lab Playbooks

Use these playbooks to stage concrete, lab-only attack simulations. Each playbook is intentionally narrow: it should test one trust boundary at a time and produce evidence that maps cleanly back to source and tests.

## Common Rules

Before running any playbook:
- confirm the environment is isolated and authorized
- snapshot current state when practical
- record exact node names, roles, and custody paths
- define the expected fail-closed outcome in advance
- stop if the action would broaden beyond the agreed lab scope

For each playbook, capture:
- preconditions
- exact commands or file mutations used
- observed runtime result
- logs or reports
- source files and tests that explain the outcome

## 1. Control-Plane Replay And Rollback

**When to use**
- signed assignments, trust evidence, traversal bundles, DNS bundles, or membership artifacts exist

**Preconditions**
- one valid current artifact
- one older or modified artifact for the same subject

**Procedure**
1. record current runtime status and active generation or watermark
2. replace the current artifact with the stale, replayed, or tampered version
3. trigger the normal reload or reconcile path
4. observe whether state is rejected, preserved, or incorrectly accepted

**Expected secure result**
- stale or tampered artifact is rejected
- current secure state remains or the system fails closed

**Evidence to collect**
- status output before and after
- validation error messages
- artifact verification logs
- unit or integration tests covering replay rejection

## 2. Local Control Surface Spoofing

**When to use**
- local clients connect to a daemon or helper over a Unix socket

**Preconditions**
- a non-production test user or temp runtime directory

**Procedure**
1. create an attacker-owned or insecure socket path in a temp area
2. make the parent directory symlinked or group/world writable
3. point the client at that path if the interface allows explicit path selection
4. observe whether the client rejects the path before connecting

**Expected secure result**
- client refuses the path based on ownership, symlink, or permission checks

**Evidence to collect**
- client error message
- file metadata for the spoofed path
- code references for socket validation

## 3. Host Trust Downgrade

**When to use**
- automation reaches remote lab nodes over SSH

**Preconditions**
- pinned host keys for the lab nodes

**Procedure**
1. replace the host key for one lab VM or point the IP at a different VM
2. re-run the provisioning or test harness against the pinned entry
3. observe whether the connection hard-fails

**Expected secure result**
- connection is refused with a host-identity error
- no TOFU or auto-accept path is taken

**Evidence to collect**
- harness error output
- pinned known_hosts entry
- code path or wrapper enforcing host-key checks

## 4. Route Or Exit Hijack

**When to use**
- the system supports exit selection, route advertisement, or path programming

**Preconditions**
- one valid route or exit configuration

**Procedure**
1. attempt to introduce an unexpected route, endpoint, or exit selection artifact
2. trigger reconcile or reload
3. inspect the programmed route set and selected path

**Expected secure result**
- unauthorized route or exit state is rejected
- data plane does not widen beyond signed or authorized state

**Evidence to collect**
- route tables before and after
- selected exit or endpoint status
- policy or assignment verification logs

## 5. DNS Integrity And Namespace Abuse

**When to use**
- managed DNS is implemented through signed state

**Preconditions**
- one valid DNS bundle and verifier key

**Procedure**
1. install a stale or mismatched DNS bundle
2. query a managed name and a non-managed name
3. optionally try a record whose target node does not justify the address

**Expected secure result**
- managed name fails closed when the bundle is stale or invalid
- unauthorized mapping is rejected
- non-managed names are refused by the authoritative path

**Evidence to collect**
- resolver outputs
- daemon status or inspect output
- bundle verification logs

## 6. Traversal Hint Or Relay Abuse

**When to use**
- the system accepts signed traversal bundles or relay/direct path transitions

**Preconditions**
- one direct-capable or relay-backed test path

**Procedure**
1. install a tampered or stale traversal bundle, or force relay mode in a controlled way
2. trigger reconcile and observe direct or relay selection
3. verify whether direct promotion requires fresh handshake evidence

**Expected secure result**
- stale or forged hints are rejected
- relay failback occurs only with fresh evidence

**Evidence to collect**
- netcheck or status outputs
- traversal logs
- source locations for probe freshness enforcement

## 7. Secret Custody And Log Leakage

**When to use**
- the system handles passphrases, signing keys, temp files, or service credentials

**Preconditions**
- access to the isolated lab host filesystem and logs

**Procedure**
1. exercise a refresh or issuance flow that materializes sensitive state
2. inspect temp directories, service runtime credentials, and logs after completion
3. confirm whether any plaintext secret remains or was logged

**Expected secure result**
- secrets are encrypted or OS-protected at rest
- temp files are tightly permissioned and scrubbed
- logs do not contain plaintext secret material

**Evidence to collect**
- file modes and ownership
- log excerpts without secrets
- tests that assert redaction or secure temp handling

## 8. Missing-State Fail-Closed Validation

**When to use**
- trust-critical state can be removed or blocked in a lab

**Preconditions**
- a working baseline state and a restoration path

**Procedure**
1. remove or invalidate one required trust input
2. trigger the normal runtime path
3. observe whether the system becomes restrictive or permissive

**Expected secure result**
- relevant operation fails closed
- no legacy, manual, or insecure fallback path is taken

**Evidence to collect**
- runtime status
- gate output
- exact error or enforcement path

## 9. Privileged Helper Input Abuse

**When to use**
- a privileged helper accepts structured commands from an unprivileged component

**Preconditions**
- negative-test harness or fuzz-like request path in a lab

**Procedure**
1. send malformed, oversized, or schema-invalid requests through the supported test path
2. observe whether the helper rejects before any privileged action occurs

**Expected secure result**
- request is rejected deterministically
- no shell interpretation or partial privileged execution occurs

**Evidence to collect**
- helper response or log
- negative test outputs
- source validation routines

## 10. Release Evidence Integrity

**When to use**
- the project ships provenance, OS matrix reports, or generated security evidence

**Preconditions**
- current source state and previously generated evidence

**Procedure**
1. verify evidence against the current commit
2. inspect report source paths for portability
3. substitute stale or mismatched evidence where safe in the lab

**Expected secure result**
- stale or mismatched evidence is rejected
- canonical source paths are required

**Evidence to collect**
- gate output
- report commit binding
- source-path references within the report
