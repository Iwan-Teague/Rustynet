# Serialization Format Hardening Plan

Date: 2026-03-25
Owner: Rustynet engineering
Status: proposed migration reference

## AI Implementation Prompt

```text
You are the implementation agent for the remaining work in this document.
Repository root: /Users/iwanteague/Desktop/Rustynet

Mission:
Complete the remaining in-scope work in this file in one uninterrupted execution if feasible. Security is the top priority. Do not stop at planning if you can still write, test, and verify code safely.

Mandatory reading order:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. This document
7. Directly linked scope/design docs and the code you will touch

Non-negotiables:
- one hardened execution path for each security-sensitive workflow
- fail closed on missing, stale, invalid, replayed, or unauthorized state
- no insecure compatibility paths, no legacy fallback branches, and no weakening of tests to make results pass
- no TODO/FIXME/placeholders for in-scope deliverables
- do not mark work complete until code, tests, and evidence exist

Execution workflow:
1. Read this document fully and convert every unchecked, open, pending, partial, or blocked item into a concrete checklist.
2. Execute the remaining work in the ordered sequence listed below.
3. Implement in small, verifiable increments, but continue until the remaining in-scope slice is complete or a real external blocker stops you.
4. After every material code change:
   - run targeted unit and integration tests for touched crates and modules
   - run smoke tests, dry runs, or CLI/service validators for the exact workflow you changed
   - rerun the most relevant gate before moving on
5. After every completed item:
   - update this document immediately instead of maintaining a separate private checklist
   - mark checkboxes and status blocks complete only after verification
   - append concise evidence: files changed, tests run, artifacts produced, residual risk, and blocker state if any
   - keep any existing session log, evidence table, acceptance checklist, or status summary current
6. Before claiming completion:
   - run repository-standard gates when the scope is substantial:
     cargo fmt --all -- --check
     cargo clippy --workspace --all-targets --all-features -- -D warnings
     cargo check --workspace --all-targets --all-features
     cargo test --workspace --all-targets --all-features
     cargo audit --deny warnings
     cargo deny check bans licenses sources advisories
   - run the scope-specific validations listed below
   - if live or lab validation is available, run it; if it is not available, do not fake success and record the blocker precisely
7. If a test or gate fails, fix the root cause. Never weaken the check, bypass the security control, or mark a synthetic path as good enough.

Document-specific execution order:
1. Execute the migration in strict phase order: Phase A schema-first hardening, then Phase B helper IPC, then Phase C artifact migration, then Phase D measured-stream migration, then Phase E DNS signer-input migration.
2. Do not introduce long-lived dual-reader or dual-writer runtime fallback paths; converters may exist only as one-shot migration tools.
3. After each phase, update the documentation touchpoints listed in Section 12 before moving to the next phase.
4. Treat privileged helper IPC and signer-adjacent input as the highest security boundaries in this plan.
5. Prefer deleting dynamic serde_json::Value handling on privileged or trust-adjacent paths before changing formats on disk.

Scope-specific validation for this document:
- Targeted tests for helper IPC malformed frame, truncated payload, unknown version, oversize payload, and trailing-byte rejection.
- Targeted tests for discovery, report, and evidence artifact readers and validators.
- ./scripts/ci/phase10_gates.sh and ./scripts/ci/membership_gates.sh when artifact readers used by those gates change.
- Any live-lab or cross-network report generation dry runs needed to prove the new format path works.

Definition of done for this document:
Completed phases have no active JSON fallback path, typed schemas replace dynamic privileged parsing in the touched scope, and every updated document or gate consumes the hardened format path described here.

If full completion is impossible in one execution, continue until you hit a real external blocker, then mark the exact remaining items as blocked with the reason, the missing prerequisite, and the next concrete step.
```

## Current Open Work

This block is the quick source of truth for what remains in this document.
If historical notes later in the file conflict with this block, the AI prompt, or current code reality, update the stale section instead of following the stale note.

`Open scope`
- This entire plan is still open unless a phase is explicitly marked completed with evidence.
- The execution order is strict: Phase A typed-schema hardening, then Phase B helper IPC, then Phase C artifacts, then Phase D measured streams, then Phase E DNS signer input.

`Do first`
- Start with Phase A by removing dynamic serde_json::Value handling on privileged or trust-adjacent paths.
- Then move to the framed postcard helper IPC migration before touching lower-risk artifact families.

`Completion proof`
- Touched phases have concrete code, tests, updated docs, and no long-lived JSON fallback in the active runtime path.
- Privileged helper parsing and signer-adjacent parsing are typed, bounded, and fail closed.

`Do not do`
- Do not create indefinite dual JSON and binary runtime readers.
- Do not migrate low-risk artifacts before the privileged helper or typed-schema hardening work.

`Clarity note`
- If a format change would preserve a weaker parser path for compatibility, reject that design and use a one-shot converter instead.

## 1) Purpose

Replace the remaining security-relevant and performance-relevant JSON surfaces in Rustynet with formats that better match each trust boundary.

This plan is not a blanket "remove all JSON" directive. The goal is stricter parsing, lower overhead, clearer boundary separation, and fewer weak generic parsing paths while preserving interoperability where JSON is the correct ecosystem format.

## 2) Scope and non-goals

In scope:
- local privileged IPC message encoding,
- machine-generated machine-consumed report artifacts,
- discovery bundles,
- append-only measured evidence streams that are currently NDJSON,
- signer-adjacent JSON inputs that feed signed state generation,
- documentation and gate updates required to keep the migration coherent.

Out of scope:
- replacing the existing signed control-plane bundle wire formats that are already canonical text and are not JSON,
- replacing JSON purely for cosmetic reasons where no security, determinism, or performance benefit exists,
- weakening interoperability with external tooling just to reduce JSON usage.

## 3) Source-of-truth and related operations docs

Normative precedence for this plan:
1. [Requirements.md](../../Requirements.md)
2. [SecurityMinimumBar.md](../../SecurityMinimumBar.md)
3. [phase10.md](../../phase10.md)
4. this plan and the related migration documents below

This plan is intentionally linked to the larger migration and hardening work already underway:
- [ShellToRustMigrationPlan_2026-03-06.md](./ShellToRustMigrationPlan_2026-03-06.md)
- [SecurityHardeningBacklog_2026-03-09.md](./SecurityHardeningBacklog_2026-03-09.md)
- [MeasuredEvidenceGeneration.md](../MeasuredEvidenceGeneration.md)
- [CrossNetworkRemoteExitArtifactSchema_2026-03-16.md](../CrossNetworkRemoteExitArtifactSchema_2026-03-16.md)
- [LiveLinuxLabOrchestrator.md](../LiveLinuxLabOrchestrator.md)
- [MagicDnsSignedZoneSchema_2026-03-09.md](./MagicDnsSignedZoneSchema_2026-03-09.md)
- [UdpHolePunchingImplementationBlueprint_2026-03-07.md](./UdpHolePunchingImplementationBlueprint_2026-03-07.md)
- [CrossNetworkRemoteExitNodePlan_2026-03-16.md](./CrossNetworkRemoteExitNodePlan_2026-03-16.md)

## 4) Security-first format selection rules

Every format migration in this repository must preserve the following constraints:

1. One hardened parser path per boundary.
   - No indefinite dual-reader runtime paths for old and new formats in production flows.
   - Temporary converters are acceptable during migration.
   - Runtime fallback from strict format A to legacy format B is not acceptable.

2. Typed schemas only on trust-sensitive or privileged paths.
   - Avoid generic `serde_json::Value` or unbounded dynamic object walking on sensitive boundaries.
   - Use explicit structs or explicit field parsers.

3. Canonical serialization whenever signatures, hashes, or replay markers are involved.
   - If a file can become provenance-bound, signed, or hash-compared, its encoding must be deterministic.

4. Bounded decode and bounded frame sizes.
   - Every parser must have maximum input size rules.
   - Stream formats must use explicit framing or an append-safe sequence format.

5. Reject ambiguity.
   - Reject trailing bytes when the format does not permit them.
   - Reject unknown fields on trust-adjacent inputs.
   - Reject malformed indices, sparse arrays, and duplicate semantic fields.

6. Keep human-readable output separate from machine artifacts.
   - Binary machine artifacts are acceptable.
   - Human-facing inspection should come from an explicit Markdown or text projection command, not by weakening the machine format.

7. Preserve secure custody behavior.
   - Existing atomic write, `fsync`, owner-only mode, and no-symlink rules must remain in force after format migration.

## 5) Current state

Rustynet does not rely on JSON everywhere.

The most trust-sensitive signed control bundles are already canonical text payloads:
- signed bundle parsing in [crates/rustynetd/src/fetcher.rs](../../../crates/rustynetd/src/fetcher.rs)
- signed auto-tunnel payload serialization in [crates/rustynet-control/src/lib.rs](../../../crates/rustynet-control/src/lib.rs)
- traversal coordination serialization in [crates/rustynet-control/src/lib.rs](../../../crates/rustynet-control/src/lib.rs)

Representative examples:
- [fetcher.rs:185](../../../crates/rustynetd/src/fetcher.rs#L185)
- [lib.rs:2741](../../../crates/rustynet-control/src/lib.rs#L2741)
- [lib.rs:2874](../../../crates/rustynet-control/src/lib.rs#L2874)

That means the JSON replacement target is not the core signed assignment/traversal/trust path. The highest-value JSON surfaces are instead:
- privileged helper IPC,
- discovery and cross-network evidence bundles,
- live-lab and phase report artifacts,
- NDJSON measured evidence streams,
- the DNS-zone records input passed into signed DNS bundle issuance.

## 6) Format options and decisions

| Format | Best fit | Security posture | Performance | Human readability | Decision |
|---|---|---:|---:|---:|---|
| Canonical UTF-8 key=value text | signed bundles, signer-adjacent manifests, simple deterministic config | high if parser is strict and minimal | high enough | strong | keep and expand selectively |
| `postcard` | local IPC frames between Rust components | high for typed bounded messages | very high | none | adopt for privileged helper IPC |
| Canonical CBOR (`.cbor`) | machine-generated machine-consumed artifact files | high with typed schema and canonical encoding | high | poor | adopt for stored artifacts and discovery bundles |
| CBOR sequence (`.cborseq`) | append-only measured evidence streams | high with typed record schema | very high for streaming | poor | adopt for large append-only source evidence |
| JSON | external ecosystem interchange and legacy artifact compatibility only | mixed | moderate | strong | keep only where interoperability requires it |
| YAML | operator-facing text config | weak relative to alternatives | low | strong | reject |
| MessagePack | general binary interchange | moderate | high | poor | not chosen |
| `bincode` v2 | tightly coupled internal Rust binary blobs | moderate | high | none | not for persisted repo artifacts; acceptable only if a narrower IPC case beats `postcard` |
| Protobuf | multi-language external APIs | high but schema-heavy | high | poor | not chosen for current repo needs |

## 7) Why a blanket switch to one format is the wrong move

Rustynet has multiple serialization boundaries with different requirements:

- A local root-owned Unix socket does not need a human-readable wire format.
- A measured evidence artifact should be compact, deterministic, and schema-versioned.
- A signer-adjacent operator input should be human-reviewable and easy to validate with one strict parser.
- A release SBOM or provenance file may need to stay JSON because the broader ecosystem expects it.

Security is improved by choosing one hardened format per boundary, not by forcing one format onto all boundaries.

## 8) Recommended target format by project area

### 8.1 Signed control-plane bundles

Current state:
- Already canonical text, not JSON.

Representative files:
- [crates/rustynetd/src/fetcher.rs](../../../crates/rustynetd/src/fetcher.rs)
- [crates/rustynet-control/src/lib.rs](../../../crates/rustynet-control/src/lib.rs)

Recommendation:
- Do not replace.
- Keep the current canonical text bundle format for signed assignment, traversal, DNS-zone, trust, and related control-plane payloads.

Why:
- deterministic field order is already explicit,
- easy to inspect in incident response,
- simple parser surface,
- already aligned with watermark/signature handling,
- already easier to review than JSON object trees for signed content.

Additional hardening still worth doing:
- move shared bundle parsing/serialization into one dedicated crate if it is still duplicated,
- keep field-ordering and canonical rendering tests,
- keep line-oriented parsers strict and reject malformed records early.

### 8.2 Privileged helper IPC

Current state:
- newline-delimited JSON request/response on the local Unix socket.

Representative files:
- [crates/rustynetd/src/privileged_helper.rs](../../../crates/rustynetd/src/privileged_helper.rs)
- [crates/rustynetd/src/phase10.rs](../../../crates/rustynetd/src/phase10.rs)

Representative current code:
- [privileged_helper.rs:178](../../../crates/rustynetd/src/privileged_helper.rs#L178)
- [privileged_helper.rs:203](../../../crates/rustynetd/src/privileged_helper.rs#L203)
- [privileged_helper.rs:427](../../../crates/rustynetd/src/privileged_helper.rs#L427)

Recommended replacement:
- `postcard` with explicit framed messages.

Recommended framing:
- magic bytes,
- schema version byte,
- message type byte,
- length prefix,
- bounded payload,
- `postcard`-encoded typed request/response structs.

Why this is the best choice here:
- this is a local Rust-to-Rust IPC boundary,
- no human readability is needed,
- messages are small and latency-sensitive,
- size limits are easier to enforce on fixed frames than on newline JSON,
- typed binary messages eliminate generic object parsing,
- there is no benefit in keeping textual JSON on a root-owned helper socket.

Security requirements for this migration:
- one parser path only,
- decode rejects trailing bytes,
- explicit max message size lower than the current JSON allowance unless there is a demonstrated need,
- version mismatch fails closed,
- no compatibility fallback to legacy JSON in the active runtime path.

Priority:
- P0

### 8.3 Cross-network discovery bundles

Current state:
- pretty-printed JSON file collected on a host and later validated and consumed by Rustynet tooling.

Representative files:
- [crates/rustynet-cli/src/bin/collect_network_discovery_info.rs](../../../crates/rustynet-cli/src/bin/collect_network_discovery_info.rs)
- [crates/rustynet-cli/src/ops_network_discovery.rs](../../../crates/rustynet-cli/src/ops_network_discovery.rs)

Representative current code:
- [collect_network_discovery_info.rs:210](../../../crates/rustynet-cli/src/bin/collect_network_discovery_info.rs#L210)
- [ops_network_discovery.rs:176](../../../crates/rustynet-cli/src/ops_network_discovery.rs#L176)

Recommended replacement:
- canonical CBOR file (`.cbor`) for the machine artifact,
- Markdown summary (`.md`) generated from the CBOR for operator review.

Why this is the best choice here:
- discovery bundles are machine-generated and machine-consumed,
- they are large enough that JSON pretty-printing is wasteful,
- they already have a strict schema and validation story,
- a deterministic binary envelope is better if later hashing, signing, or provenance-binding is added,
- human readability can be preserved via an explicit `render-discovery-summary` command instead of by keeping the machine artifact as JSON.

Security requirements:
- typed struct schema with explicit version,
- canonical field ordering,
- duplicate semantic fields rejected,
- strict no-secrets validation retained,
- file mode remains owner-only where appropriate.

Priority:
- P1

### 8.4 Cross-network, live-lab, and phase report artifacts

Current state:
- large JSON artifact family across live-lab, cross-network, phase1, phase6, phase9, phase10, and fresh-install matrix generation.

Representative files:
- [crates/rustynet-cli/src/ops_cross_network_reports.rs](../../../crates/rustynet-cli/src/ops_cross_network_reports.rs)
- [crates/rustynet-cli/src/ops_live_lab_failure_digest.rs](../../../crates/rustynet-cli/src/ops_live_lab_failure_digest.rs)
- [crates/rustynet-cli/src/ops_fresh_install_os_matrix.rs](../../../crates/rustynet-cli/src/ops_fresh_install_os_matrix.rs)
- [crates/rustynet-cli/src/ops_phase1.rs](../../../crates/rustynet-cli/src/ops_phase1.rs)
- [crates/rustynet-cli/src/ops_phase9.rs](../../../crates/rustynet-cli/src/ops_phase9.rs)
- [crates/rustynet-cli/src/bin/live_lab_support/mod.rs](../../../crates/rustynet-cli/src/bin/live_lab_support/mod.rs)

Representative current code:
- [ops_cross_network_reports.rs:1](../../../crates/rustynet-cli/src/ops_cross_network_reports.rs#L1)
- [ops_fresh_install_os_matrix.rs:119](../../../crates/rustynet-cli/src/ops_fresh_install_os_matrix.rs#L119)
- [ops_phase9.rs:3921](../../../crates/rustynet-cli/src/ops_phase9.rs#L3921)
- [live_lab_support/mod.rs:74](../../../crates/rustynet-cli/src/bin/live_lab_support/mod.rs#L74)

Recommended replacement:
- canonical CBOR (`.cbor`) for the machine artifact,
- Markdown (`.md`) retained for human digests and triage,
- if a text machine export is ever needed, produce it from CBOR as a derived artifact, not as the primary stored artifact.

Why:
- these artifacts are overwhelmingly machine-generated,
- they already have schema-like expectations and strict validations,
- the current JSON-heavy path encourages broad use of `serde_json::Value`,
- canonical CBOR is more suitable for long-lived internal artifacts than pretty JSON,
- artifact families become easier to unify under one shared artifact envelope.

Recommended envelope fields for all CBOR artifacts:
- `schema_id`
- `schema_version`
- `artifact_family`
- `artifact_kind`
- `evidence_mode`
- `captured_at_unix`
- `git_commit`
- typed payload
- typed source artifact list

Priority:
- P1 for cross-network and live-lab artifacts,
- P2 for the wider phase report family once the shared artifact crate exists.

### 8.5 Append-only measured evidence streams

Current state:
- several measured source inputs are documented as NDJSON.

Representative documented paths:
- `artifacts/perf/phase1/source/performance_samples.ndjson`
- `artifacts/operations/source/slo_windows.ndjson`
- `artifacts/operations/source/performance_samples.ndjson`
- `artifacts/operations/source/incident_drills.ndjson`
- `artifacts/operations/source/dr_drills.ndjson`

Relevant operations doc:
- [MeasuredEvidenceGeneration.md](../MeasuredEvidenceGeneration.md)

Recommended replacement:
- CBOR sequence (`.cborseq`) for append-only streaming records.

Why this is the best choice here:
- these are append-only machine-generated evidence streams,
- line-oriented JSON is convenient but inefficient for large repeated records,
- CBOR sequence keeps streaming/appending behavior while reducing parse overhead and storage size,
- record schemas can stay versioned and typed per stream family.

Why not single-file CBOR here:
- append-only streams are better represented as a sequence of individually decodable typed records than as one growing monolithic document.

Security requirements:
- one record type per stream family,
- explicit per-record schema version,
- bounded record size,
- strict EOF and truncation handling,
- tooling must fail closed on malformed records rather than skipping them silently.

Priority:
- P2

### 8.6 Signer-adjacent DNS records input

Current state:
- `rustynet dns zone issue` accepts `--records-json <path>`.

Representative files:
- [crates/rustynet-cli/src/main.rs](../../../crates/rustynet-cli/src/main.rs)
- [crates/rustynet-cli/src/bin/live_linux_managed_dns_test.rs](../../../crates/rustynet-cli/src/bin/live_linux_managed_dns_test.rs)
- [crates/rustynet-cli/src/bin/live_linux_exit_handoff_test.rs](../../../crates/rustynet-cli/src/bin/live_linux_exit_handoff_test.rs)
- [README.md](../../../README.md)

Representative current code:
- [main.rs:9497](../../../crates/rustynet-cli/src/main.rs#L9497)
- [main.rs:10116](../../../crates/rustynet-cli/src/main.rs#L10116)
- [live_linux_exit_handoff_test.rs:1012](../../../crates/rustynet-cli/src/bin/live_linux_exit_handoff_test.rs#L1012)

Recommended replacement:
- canonical text manifest, not JSON.

Recommended direction:
- replace `--records-json` with `--records-manifest`,
- use the same strict UTF-8 `key=value` discipline Rustynet already uses for signed control-plane bundles,
- keep the manifest human-reviewable and signer-adjacent.

Example shape:
```text
version=1
record_count=2
record.0.label=app
record.0.target_node_id=node-a
record.0.ttl_secs=60
record.0.alias_count=1
record.0.alias.0=ssh
record.1.label=api
record.1.target_node_id=node-b
record.1.ttl_secs=60
record.1.alias_count=0
```

Why this is better than CBOR here:
- this input sits immediately upstream of signed DNS bundle issuance,
- operator review matters more than raw parse speed,
- the file is small,
- the project already has a proven pattern for strict canonical text payloads,
- a tiny explicit parser is preferable to another generic data-language parser on a signer-adjacent boundary.

Why this is better than keeping JSON:
- removes dynamic array/object parsing from a signer-adjacent input,
- removes generic "strict object" parsing complexity from the active path,
- aligns with the rest of the control-plane text serialization model.

Priority:
- P0

### 8.7 External ecosystem and standards-bound JSON

Current state:
- some JSON surfaces are interoperability artifacts, not internal transport decisions.

Examples:
- release provenance,
- cargo metadata JSON,
- SBOM-related JSON,
- other external-tool-consumed outputs where JSON is the established format.

Representative files and references:
- `artifacts/release/rustynetd.provenance.json`
- `artifacts/release/sbom.cargo-metadata.json`
- `documents/operations/dependency_exceptions.json`

Recommendation:
- keep JSON here unless there is a compelling ecosystem-supported replacement.

Why:
- these files exist partly to interoperate with external tools and reviewers,
- replacing them with an internal-only binary format would reduce usability without buying real security,
- the security win here comes from provenance verification and custody, not from switching away from JSON.

Priority:
- no migration recommended

### 8.8 Test-only and mock-only JSON surfaces

Current state:
- some JSON parsing in tests or mock helpers exists only to exercise current runtime behavior.

Representative file:
- [crates/rustynetd/src/phase10.rs](../../../crates/rustynetd/src/phase10.rs)

Representative current code:
- [phase10.rs:3416](../../../crates/rustynetd/src/phase10.rs#L3416)

Recommendation:
- migrate these only when the runtime surface they emulate is migrated.
- do not spend migration effort here ahead of the live privileged-helper IPC conversion.

Priority:
- P3

## 9) Replacement matrix

| Area | Current format | Recommended format | Priority | Why |
|---|---|---|---|---|
| Privileged helper socket IPC | newline JSON | framed `postcard` | P0 | local IPC, typed, bounded, fast |
| DNS zone signer input | JSON array | canonical text manifest | P0 | signer-adjacent, human-reviewable, strict parser |
| Discovery bundle | pretty JSON | canonical CBOR + Markdown projection | P1 | machine artifact, compact, deterministic |
| Cross-network reports | pretty JSON | canonical CBOR + Markdown projection | P1 | machine artifact, schema-heavy |
| Live-lab summary and failure digest | JSON + Markdown | canonical CBOR + Markdown | P1 | machine artifact plus human digest |
| Fresh-install OS matrix and phase report family | JSON | canonical CBOR | P2 | internal long-lived evidence |
| Raw measured source streams | NDJSON | CBOR sequence | P2 | append-only, compact, stream-friendly |
| Release/SBOM/provenance interop outputs | JSON | keep JSON | none | external ecosystem compatibility |
| Existing signed bundles | canonical text | keep canonical text | none | already the right format |

## 10) Migration architecture

Introduce one shared serialization crate rather than spreading format logic across CLI and daemon modules.

Recommended crate responsibilities:
- typed artifact envelope definitions,
- canonical CBOR encoder/decoder,
- CBOR sequence stream reader/writer,
- framed `postcard` IPC encode/decode,
- canonical text manifest parsers for small signer-adjacent manifests,
- max-size constants and decode guards,
- test vectors and negative tests,
- file-extension and schema-id constants.

Suggested crate boundary:
- `crates/rustynet-serialization/`

Design rules for that crate:
- no secret logging,
- no dynamic `Value` on privileged paths,
- explicit versioning,
- explicit decode limits,
- one public API per format family.

## 11) Migration phases

### Phase A: schema-first hardening before format swaps

Goal:
- replace dynamic `serde_json::Value` handling with typed structs wherever practical before the on-disk/on-wire format changes.

Why:
- typed schema hardening gives security benefit immediately,
- format migration becomes safer when the data model is already explicit.

Targets:
- discovery bundle validation,
- cross-network report validation,
- live-lab summary/failure digest parsing,
- fresh-install OS matrix report parsing.

### Phase B: privileged helper IPC migration

Goal:
- move the helper socket to framed `postcard`.

Required updates:
- helper client,
- helper server,
- helper tests and mocks,
- any phase10 mock helper JSON test code that assumes the old wire format.

Acceptance:
- no JSON reader remains in the active helper runtime path,
- size-limited decode and version negotiation are enforced,
- regression tests cover malformed frame, unknown version, truncated payload, oversize payload.

### Phase C: discovery and report artifact migration

Goal:
- move discovery bundles and cross-network/live-lab/phase artifacts to canonical CBOR.

Required updates:
- artifact writers,
- validators,
- gate scripts and Rust ops commands,
- artifact path constants,
- human-readable Markdown renderers.

Acceptance:
- gates consume CBOR directly,
- Markdown digests are derived from CBOR,
- no JSON is used in the active internal artifact path.

### Phase D: measured source stream migration

Goal:
- replace NDJSON measured input streams with CBOR sequence streams.

Required updates:
- phase1 source readers,
- phase9 source readers,
- measured evidence generation docs,
- any sample generators or import tools.

Acceptance:
- stream readers reject malformed/truncated records,
- source collectors emit `.cborseq`,
- measured evidence generation docs are updated accordingly.

### Phase E: DNS signer-input manifest migration

Goal:
- replace `--records-json` with `--records-manifest`.

Required updates:
- CLI parser and help text,
- README examples,
- Magic DNS schema and operational docs,
- E2E tests that currently generate temporary JSON files for DNS records.

Acceptance:
- signer-adjacent JSON input is gone from the active path,
- manifest parser rejects duplicate/sparse/unknown record fields,
- bundle issuance remains fail-closed.

## 12) Documentation touchpoints that must be updated with each phase

| Document | Why it must change |
|---|---|
| [ShellToRustMigrationPlan_2026-03-06.md](./ShellToRustMigrationPlan_2026-03-06.md) | Rust migration should include serialization hardening as part of the same privileged-path cleanup story |
| [MeasuredEvidenceGeneration.md](../MeasuredEvidenceGeneration.md) | artifact extensions and source stream formats will change |
| [CrossNetworkRemoteExitArtifactSchema_2026-03-16.md](../CrossNetworkRemoteExitArtifactSchema_2026-03-16.md) | report schema and file naming will change |
| [LiveLinuxLabOrchestrator.md](../LiveLinuxLabOrchestrator.md) | run summary, failure digest, and cross-network artifact paths will change |
| [MagicDnsSignedZoneSchema_2026-03-09.md](./MagicDnsSignedZoneSchema_2026-03-09.md) | DNS signer input path will move from JSON to canonical text manifest |
| [CrossNetworkRemoteExitNodePlan_2026-03-16.md](./CrossNetworkRemoteExitNodePlan_2026-03-16.md) | discovery and cross-network evidence capture examples will change |

## 13) Security risks and mitigations

### Risk: binary artifacts are harder for operators to inspect

Mitigation:
- every binary artifact family must have a Rust-native Markdown projection command,
- operator-facing workflows should default to generating both machine artifact and Markdown summary.

### Risk: schema drift across modules

Mitigation:
- one shared serialization crate,
- no duplicate ad hoc encoder/decoder implementations in multiple crates,
- schema ids and version constants centralized.

### Risk: migration creates a soft fallback path

Mitigation:
- converters may exist as one-shot tools,
- runtime readers must not silently accept both old and new formats indefinitely,
- gates should fail if an active path still emits legacy JSON after the migration phase is complete.

### Risk: canonical binary encoding is implemented inconsistently

Mitigation:
- publish test vectors,
- round-trip tests,
- cross-module property tests,
- single encoder implementation shared by all writers.

## 14) Recommended first implementation order

1. Privileged helper IPC: JSON -> framed `postcard`
2. DNS signer input: `--records-json` -> canonical text manifest
3. Discovery bundle: JSON -> CBOR
4. Cross-network and live-lab report family: JSON -> CBOR
5. Phase1/Phase9/Phase10 raw evidence streams: NDJSON -> CBOR sequence

Why this order:
- it removes the highest-value privileged JSON path first,
- then removes JSON from a signer-adjacent input,
- then hardens the largest internal artifact families,
- then upgrades the append-only source evidence streams after the artifact envelope work is already shared.

## 15) Recommended repository policy after migration

Once the migration is complete, Rustynet should follow this policy:

- Signed control state: canonical text bundles only
- Privileged local IPC: framed `postcard` only
- Internal machine artifacts and discovery bundles: canonical CBOR only
- Append-only measured source streams: CBOR sequence only
- Human-facing summaries: Markdown/text only
- External standards-bound interchange: JSON only where ecosystem compatibility requires it

That policy gives the project one hardened format per boundary instead of one generic format stretched across all boundaries.
## Agent Update Rules

Use these rules every time you modify this document during implementation work.

1. Update the document immediately after each materially completed slice.
- Do not keep a private checklist that diverges from this file.
- This document must remain the public execution record.

2. Mark completion conservatively.
- Use `[x]` only after the code is implemented and verified.
- Use `Status: partial` when some hardening landed but real work remains.
- Use `Status: blocked` only for real external blockers; name the blocker precisely.

3. Record evidence under the section you touched, or in the existing session log/evidence table if the document already has one.
- Minimum evidence fields:
  - `Changed files:` exact paths
  - `Verification:` exact commands, tests, smoke runs, dry runs, gates
  - `Artifacts:` exact generated paths, if any
  - `Residual risk:` what still remains, if anything
  - `Blocker / prerequisite:` only when applicable

4. Use exact timestamps and commit references where possible.
- Prefer UTC timestamps in ISO-8601 format.
- If commits exist, record the commit SHA that contains the work.

5. Do not delete historical context that still matters.
- Correct stale claims when they are inaccurate.
- Do not erase previous findings, checklist items, or session history just to make the document look cleaner.

6. Keep security claims evidence-backed.
- Never write that a path is secure, complete, hardened, or production-ready without code and verification proof.
- If live validation is unavailable, state that explicitly and record the missing prerequisite.

7. If tests fail, record the failure honestly and fix the root cause.
- Do not weaken gates, remove checks, or relabel failures as acceptable.
- If a fix is incomplete, mark the item partial instead of complete.

