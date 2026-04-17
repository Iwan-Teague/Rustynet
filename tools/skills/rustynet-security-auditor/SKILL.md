---
name: rustynet-security-auditor
description: Use when the target is specifically the Rustynet repository or a Rustynet live lab: audit Rustynet’s control plane, dataplane, DNS, traversal, and release evidence; run the canonical Rustynet live validators; correlate findings to Rustynet enforcement points; and produce reproducible hardening guidance plus coverage decisions for Rustynet exploit classes.
---

# Rustynet Security Auditor

Use this skill only for Rustynet. It is the Rustynet-specific layer above the generic network adversarial hardening workflow.

The source of truth for this skill is the version committed in the Rustynet repo under `tools/skills/rustynet-security-auditor/`. If a global installed copy exists under `~/.codex/skills`, keep it synchronized from the repo copy.

## When To Use This Skill

Use this skill when the user wants to:
- audit Rustynet specifically for security weaknesses
- run or interpret Rustynet live-lab adversarial validations
- compare Rustynet against historical exploit classes from Tailscale, WireGuard-based clients, OpenVPN, NetBird, and similar systems
- decide whether a Rustynet exploit class is still `partially_covered` or can be promoted to `covered`
- generate Rustynet-specific hardening findings with direct file and gate correlation

Do not use this skill for:
- non-Rustynet targets
- offensive activity against any non-lab network
- generic penetration testing without a Rustynet hardening objective

## Required Rustynet Context

Before doing substantial work, read:
- `README.md`
- `AGENTS.md`
- `CLAUDE.md`
- `documents/Requirements.md`
- `documents/SecurityMinimumBar.md`
- `documents/phase10.md`
- `references/rustynet-audit-surface-map.md`

Load additional references only as needed:
- `references/comparative-vpn-exploit-catalog.md`
- `references/live-lab-correlation-map.md`
- `references/attack-catalog.md`
- `references/lab-playbooks.md`
- `references/audit-checklist.md`

## Rustynet Workflow

### 1. Establish Rustynet Scope

Determine whether the task is:
- code audit only
- comparative exploit audit
- live-lab validation
- coverage-promotion decision

If the live lab is not explicitly authorized, stop at code audit and comparative analysis.

### 2. Rustynet Comparative Baseline

When the user wants exploit comparison or weakness discovery:
1. run `rustynet ops generate-comparative-exploit-coverage`
2. if useful, add `--run-local-tests`
3. inspect every `future_surface_gap` and `partially_covered` item
4. do not claim `covered` from local tests alone where the comparative mapping still requires live evidence

Default output path:
- `documents/operations/RustynetComparativeVpnExploitCoverage_<date>.md`

### 3. Rustynet Live-Lab Validation

For Rustynet live-lab work, use one hardened execution path only:
- `rustynet ops run-live-lab-validations`

Do not hand-stitch validator runs unless you are debugging the runner itself.

The runner is the canonical path because it:
- executes the selected Rustynet validators
- emits canonical JSON reports
- requires a pinned SSH `known_hosts` path and validates host-key presence before any validator starts
- verifies SSH reachability to every targeted host before any validator starts
- verifies the required remote binaries and the `rustynetd.service` unit are present before any validator starts
- validates report schema
- generates prioritized findings
- evaluates whether comparative coverage can be promoted

The schema, promotion, matrix, findings, comparative coverage, and live-runner logic now live in `rustynet-cli` ops commands. The older Python entrypoints have been retired from the repo.

Default validation set for the currently partially covered exploit classes:
- `control_surface_exposure`
- `server_ip_bypass`
- `endpoint_hijack`

### 4. Rustynet Findings And Correlation

After live execution:
1. read the generated findings markdown from `rustynet ops generate-live-lab-findings`
2. use `references/live-lab-correlation-map.md`
3. confirm the likely Rustynet enforcement points in source
4. check the relevant gates and tests before proposing fixes

Never stop at runtime symptoms. Always tie the finding to:
- the failing validator check
- the relevant Rustynet files
- the missing or weakened enforcement point
- the regression test or gate that must prove the fix

### 5. Rustynet Coverage Promotion

Only promote a comparative exploit class from `partially_covered` to `covered` if:
- the required Rustynet live validator report exists
- report schema validation passed
- the report status is `pass`
- every mandatory check passed
- the promotion gate `rustynet ops evaluate-live-coverage-promotion` returns success

If any of those conditions fail, keep the exploit class at `partially_covered`.

## Required Output

For Rustynet work, outputs should be concrete and usually written into repo-visible `.md` artifacts under `documents/operations/` unless the user asks otherwise.

Preferred output order:
1. findings
2. assumptions or open questions
3. remediation summary
4. exact verification path

Include:
- affected Rustynet subsystem
- exploit family
- exact failing validator or test
- exact Rustynet files to inspect
- fail-open vs fail-closed result
- remediation with one hardened path only

## Bundled Commands

- `rustynet ops generate-comparative-exploit-coverage`
  Generate the Rustynet exploit coverage baseline from historical VPN incidents.
- `rustynet ops run-live-lab-validations`
  Canonical Rustynet live-lab runner.
- `rustynet ops validate-live-lab-reports`
  Enforce the shared Rustynet live-report schema.
- `rustynet ops generate-live-lab-findings`
  Convert live report failures into prioritized Rustynet findings.
- `rustynet ops evaluate-live-coverage-promotion`
  Fail closed on exploit coverage promotion unless required live evidence is strong.
- `rustynet ops generate-attack-matrix`
  Create canonical attack matrices.
- `rustynet ops generate-assessment-from-matrix`
  Produce a markdown scaffold from the matrix.

## Non-Negotiable Constraints

- Rustynet only
- lab-only, authorized-only for live validations
- default-deny and fail-closed are the expected secure outcomes
- one hardened execution path per security-sensitive workflow
- no fallback or downgrade suggestions
- do not weaken Rustynet gates to make reports pass
