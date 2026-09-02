# MacosEnforceRefreshParityPlan Phase B Adversarial Review — 2026-09-02

- **Status:** Complete.
- **Subject:** Adversarial verification of `MacosEnforceRefreshParityPlan_2026-09-02.md` (Phase B review, per that plan's §6 checklist).
- **Scope:** Docs-only. No code changes, no lab run. Every code anchor re-checked by direct file read against the worktree at base commit `9c907071` (branch `ai-edit/edit-1788368507314-4519-0`).
- **Method note:** The planned cheap sub-agent fan-out was unavailable (`Model not found: opencode/deepseek-v4-flash-free`); all verification was performed directly by the reviewing agent. The finding set below is the agent's own; treat it as untrusted-adjacent and re-check any claim you act on.

## Verdict

**ACCEPT-WITH-AMENDMENTS** — with one CRITICAL, blocking amendment (F-1) and one HIGH amendment (F-2). Gap A (enforce-path refresh parity) and §3.1's design are verified sound and keep. Gap B's central claim — *no startup path re-applies the protected-DNS posture* — is **wrong**: `DaemonRuntime::bootstrap()` already re-applies the full dataplane generation, protected-DNS arm included, at every startup on both platforms. The plan must be amended to diagnose why the observed macOS bootstrap apply did not satisfy the verifier before prescribing a second apply path.

## Findings

_Filled in follow-up commits (skeleton-first commit per instruction)._

## Per-anchor verification table

_Filled in follow-up commits._

## Considered, no defect

_Filled in follow-up commits._

## Answers to the eight tasked questions

_Filled in follow-up commits._
