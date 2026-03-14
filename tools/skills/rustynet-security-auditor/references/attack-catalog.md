# Attack Catalog

Use this catalog to choose the smallest set of attack simulations that best cover the highest-risk trust boundaries.

## How To Use This Catalog

For each family:
1. state the security hypothesis
2. define the minimum lab setup
3. define the expected fail-closed behavior
4. collect runtime evidence
5. map any failure back to source and tests

Do not run every category by default. Pick the categories that meaningfully exercise the target's trust model.

## 1. Control-Plane Authenticity, Replay, And Rollback

**Goal**
- Prove that stale, replayed, downgraded, or forged control artifacts cannot mutate runtime state.

**Typical lab simulations**
- replay an old signed bundle
- substitute a bundle with a lower generation or older watermark
- remove or corrupt verifier keys
- tamper with a signed artifact after issuance

**Expected secure behavior**
- reject the artifact
- preserve current secure state or fail closed
- log an actionable validation error without secrets

**Source audit targets**
- signature verification
- nonce, epoch, watermark, max-age checks
- equality-vs-greater-than rollback logic
- artifact loading paths and temp-file custody

## 2. Local Control Surface Spoofing

**Goal**
- Prove that local clients cannot be tricked into talking to a spoofed daemon or helper surface.

**Typical lab simulations**
- symlink a Unix socket path
- create a world-writable socket or parent directory
- replace a trusted runtime socket with an attacker-owned endpoint
- race a client against a stale or malicious local IPC surface

**Expected secure behavior**
- reject the path before connecting
- verify ownership, permissions, and path integrity
- refuse insecure parents and symlinks

**Source audit targets**
- socket validation
- helper-client validation
- peer credential checks
- parent-directory trust checks

## 3. Host Trust And Bootstrap Downgrade

**Goal**
- Prove that node onboarding and automation do not silently trust a malicious or changed host identity.

**Typical lab simulations**
- swap host keys in a lab SSH target
- delete pinned trust data and observe reconnect behavior
- present a new host with the same IP

**Expected secure behavior**
- host verification fails closed
- no TOFU downgrade or auto-accept path
- operator sees a precise trust error

**Source audit targets**
- SSH wrappers and automation harnesses
- host-key handling
- setup and provisioning flows

## 4. Route, Exit, And Path Hijack

**Goal**
- Prove that an attacker cannot widen routing or redirect traffic through an unauthorized path.

**Typical lab simulations**
- inject unexpected routes
- replay or forge exit-selection state
- force ambiguous egress-interface conditions
- attempt endpoint substitution for a peer or exit path

**Expected secure behavior**
- path is rejected or reconciled back to signed state
- traffic fails closed rather than leaking
- authorization boundaries remain intact

**Source audit targets**
- route installation
- exit-selection workflows
- endpoint mutation paths
- interface auto-detection and bypass routing

## 5. DNS Integrity And Namespace Abuse

**Goal**
- Prove that managed names cannot be spoofed, silently widened, or resolved through insecure fallback paths.

**Typical lab simulations**
- install a stale signed DNS bundle
- point a name at an address not justified by signed assignment state
- query non-managed names against the authoritative resolver
- remove the verifier key or signed zone

**Expected secure behavior**
- managed names fail closed when state is missing or invalid
- unauthorized mappings are rejected
- non-managed names are refused, not guessed or forwarded through insecure local overrides

**Source audit targets**
- DNS bundle verification
- resolver bind restrictions
- host-integration path
- any `/etc/hosts` or raw resolver fallback

## 6. NAT Traversal And Relay Abuse

**Goal**
- Prove that endpoint hints, relay activation, and failback decisions cannot be forged or widened.

**Typical lab simulations**
- tamper with traversal bundles
- inject stale endpoint hints
- force relay mode and observe reprobe behavior
- attempt direct-path promotion without fresh handshake evidence

**Expected secure behavior**
- traversal artifacts are verified and bounded
- direct promotion requires fresh evidence
- relay fallback is explicit and authorized
- reprobe logic does not trust stale cached state

**Source audit targets**
- traversal bundle verification
- handshake evidence freshness
- relay/direct mode transitions
- reprobe cadence and promotion logic

## 7. Secret Custody And Log Leakage

**Goal**
- Prove that secrets do not leak through files, temp paths, environment, argv, or logs.

**Typical lab simulations**
- inspect temp paths and service credentials during refresh flows
- review logs after failed operations
- scan for world-readable files in runtime custody paths

**Expected secure behavior**
- encrypted-at-rest or OS-protected storage only
- strict file modes and ownership
- no plaintext passphrases in logs or long-lived files

**Source audit targets**
- credential materialization
- temp-file handling
- secure delete or scrub paths
- debug logging and structured event emission

## 8. Fail-Closed Behavior Under Missing Or Invalid State

**Goal**
- Prove that the system becomes restrictive, not permissive, when required trust inputs disappear.

**Typical lab simulations**
- remove signed assignment state
- remove trust evidence or verifier keys
- block a refresh path and observe runtime
- stop a DNS or membership update path

**Expected secure behavior**
- no silent fallback to legacy or manual paths
- tunnel, DNS, or privileged mutations fail closed
- the error is explicit and diagnosable

**Source audit targets**
- `fallback`, `legacy`, `compat`, `auto-detect`, `best-effort`
- shell wrappers around Rust commands
- manual mutation paths that bypass signed control state

## 9. Privileged Helper Input Abuse

**Goal**
- Prove that helper boundaries cannot be crossed with argument injection or schema abuse.

**Typical lab simulations**
- malformed request frames
- oversized arguments
- invalid token sequences
- command-schema mismatch attempts

**Expected secure behavior**
- strict parser rejection
- bounded argument counts and sizes
- no shell interpretation

**Source audit targets**
- helper schemas
- input validation
- argv-only exec paths
- fuzz or negative tests

## 10. Supply Chain And Release Evidence Integrity

**Goal**
- Prove that release evidence, provenance, and generated security artifacts are bound to the correct source state.

**Typical lab simulations**
- verify artifact provenance against the wrong commit
- swap a generated report while preserving filenames
- depend on untracked local evidence paths

**Expected secure behavior**
- commit binding is explicit
- evidence paths are canonical and portable
- stale or mismatched evidence fails the gate

**Source audit targets**
- gate scripts
- artifact generation
- provenance signing and verification
- report source-path references
