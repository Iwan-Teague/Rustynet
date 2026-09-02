# macOS Exit Killswitch-Precedence Artifact Freshness Plan (2026-09-02)

**Status:** PLANNING (docs-only; no code changed in this document's creation).
Closes follow-up **F2 (Low-Med — evidence freshness)** from
[`MacosExitServingAdapterWiringPostMergeReview_2026-09-02.md`](./MacosExitServingAdapterWiringPostMergeReview_2026-09-02.md:215)
(":215-228). The finding: the macOS exit killswitch-precedence artifact has no
freshness binding, so a leftover valid-shape file at the fixed path could be
read as a fresh pass if the daemon ever exited 0 without rewriting it.

**Chosen fix: Option A — the daemon prints the artifact verbatim on stdout and
the adapter captures it fresh (capture-over-SSH, no fixed-path read at all).**
Option B (schema `captured_at_unix` + per-run nonce, evaluator asserts
recency/nonce-match) is specified and rejected below as the weaker binding.

---

## 1) The exact fail-open window

## 2) Security precedence call — product defect or lab-only residue?

## 3) Two candidate fixes, strictest chosen

## 4) Offline-testable core for the chosen fix

## 5) Crates changed + collision surface

## 6) Live-lab proof stage and unknowns
