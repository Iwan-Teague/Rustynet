<!-- Drafted 2026-09-07 by a glm-5.3-flash grounded read-only agent at the owner's request (owner decision 7); reviewed and placed by the managing Claude session. Status: PLAN — implementation tracked in OwnerDecisions_2026-09-07.md. Line references are against main at 2a5c4e1d unless stated. -->

# Implementation plan: mechanical path allowlist for delegated-edit (GLM) jobs

## Goal

Constrain every `ai_edit_run` job to a per-job allowlist of path prefixes, enforced mechanically at commit time and at checkpoint time, so an out-of-allowlist edit (2026-09-07: a timed-out auto-checkpoint carried an unauthorised change to `crates/rustynet-cli/src/main.rs`) can never be committed to the job branch, and ends the job in a distinct `scope_violation` state with the offending diff attached.

## Existing state

- Worktrees: `EDIT_WORKTREES_SUBDIR = "state/edit-worktrees"` (`ai_agent.rs:466`); `create_edit_worktree` (`ai_agent.rs:2210`) does `git worktree add -b ai-edit/<job>` (`:2242`); `spawn_opencode_serve` runs `opencode serve --port 0` with cwd = worktree (`:2297-2300`) — cwd is the only scoping OpenCode gets.
- Params: `call_edit_run` (`:2599`) accepts `task`/`mode` (`:2621`, maps to agents `rustynet-edit-full`/`-restricted` at `:2630-2633`) and `base_ref` (`:2651`); schema at `:7798-7806`. **No path scoping exists anywhere.**
- Root cause of the incident, confirmed in code: `checkpoint_edit_worktree` (`:3255`) does `git add -A` then `git commit --no-verify` (`:3268-3285`). `add -A` takes every dirty file; `--no-verify` bypasses any hook. It is called from `persist_edit_diff` (`:3291`) on the timeout paths (`:2913-2919`, `:2983-2990`). So even a perfect hook could not have stopped this specific path.
- Hooks: `scripts/git-hooks/pre-commit` enforces staleness + the AGENTS/CLAUDE mirror guard; `scripts/git-hooks/install.sh:8` sets `core.hooksPath` per-clone — untracked config, absent unless the owner ran it, and worktrees inherit it only from the shared clone config. `ai_agent.rs` contains no hook installation (grep: only an unrelated comment at `:5717`).
- Job states: terminal arms at `:2885` (`"done" | "timed_out" | "halted_budget" | "provider_error"`) and verdict map at `:3307-3313`. `mark_edit_terminal` (`:3231`), diff capture `edit_job_diff` (`:2554`), records via `write_job_record` (`:834`).
- OpenCode permissions: `.opencode/opencode.json` permission maps are **tool-level strings only** (`"edit": "allow"` / `"ask"` / `"deny"`); no path-scoped entries exist in the repo, and the schema (`$schema: https://opencode.ai/config.json`) is remote — **I could not reach it from this environment, so I cannot confirm path-scoped edit permissions are supported.** Treat layer 2 as unverified.

## Design

**`crates/rustynet-mcp/src/bin/ai_agent.rs`** (all changes):

1. `const DEFAULT_EDIT_PATH_ALLOWLIST: &[&str] = &["crates/rustynet-cli/src/vm_lab/**", "documents/**", "scripts/vm_lab/**", "scripts/mcp/**"];` (next to `:466`).
2. Pure matchers, unit-testable without git:
```rust
/// `**` matches any remainder. A rule without `**` is a directory prefix
/// (rule `documents` covers `documents/x.md`). Any path containing a `..`
/// component matches nothing — fail closed.
fn path_in_allowlist(rel: &str, rules: &[String]) -> bool
fn classify_porcelain(status: &str, rules: &[String]) -> (Vec<String>, Vec<String>)
```
   No glob crate exists in `crates/rustynet-mcp/Cargo.toml` (`[dependencies]` at `:24`) — hand-roll the suffix match, ~30 lines, no new dep.
3. `call_edit_run` + schema (`:7798`): optional `path_allowlist: string[]`; validate each rule (relative, non-empty, no `..`, reject rules matching nothing) else **deny the call**; default to `DEFAULT_EDIT_PATH_ALLOWLIST`. Store in the job record as `path_allowlist`.
4. `create_edit_worktree` (`:2210`): after `git worktree add`, write `state/edit-worktrees/<job>/allowlist.txt` (one rule per line), and install a per-worktree hook at `<repo>/.git/worktrees/<job>/hooks/pre-commit` (linked worktrees consult `$GIT_DIR/hooks` when `core.hooksPath` is unset): reads allowlist positionally from the worktree root (derive job dir via `git rev-parse --show-toplevel`), runs `git diff --cached --name-only -- others` logic, exits 1 naming any out-of-allowlist path; missing/unreadable allowlist file ⇒ exit 1; then execs `scripts/git-hooks/pre-commit` if present so the staleness/mirror guards still run.
5. `checkpoint_edit_worktree` (`:3255`): take `rules: &[String]`; classify `git status --porcelain` output; if the out-of-scope set is non-empty: `git add --` **only** in-scope paths, commit those (keep `--no-verify` — scope is enforced programmatically here, the hook cannot be trusted to run), record `scope_violations: [...]` and `out_of_scope_diff` (`git diff <base_ref> -- <out paths>` plus untracked file contents via `edit_job_diff`-style capture), and leave out-of-scope files uncommitted in the worktree.
6. `persist_edit_diff` / timeout paths: if `scope_violations` non-empty, `mark_edit_terminal(rec, "scope_violation", Some("edits outside the path allowlist"))`; add `"scope_violation"` to the arms at `:2885` and `"SCOPE VIOLATION"` to the verdict map at `:3307-3313`, and render `out_of_scope_diff` in `edit_terminal_summary`.

**`.opencode/opencode.json`**: add one advisory sentence to the `rustynet-edit-full`/`-restricted` prompts ("edit only inside the brief's allowlist; out-of-allowlist edits fail the job"). No permission-schema change — unverified (see Open questions).

## Security analysis

- Fail closed: empty/invalid/unreadable allowlist denies (hook exit 1; matcher returns false on `..`); `scope_violation` is distinct from `done`, so it cannot be skim-read as success.
- Enforcement boundary is the checkpoint (server control flow, in-process), not the hook: the agent can `commit --no-verify`, but it cannot merge — human review remains the final gate, unchanged.
- New trust boundary: none crossed; allowlist travels in the job record and a worktree-local file, positionally derived, not env-spoofable via the agent shell.
- Residual: `main.rs` (1.19 MB, the shipped CLI) is *not* in the default allowlist — deliberate, per the incident. Briefs needing more surface must pass an explicit `path_allowlist`, which is auditable in the record.

## Tests

Unit (`mod tests`, `ai_agent.rs:8042`): matcher (in/out, `documents` vs `documents_evil/x`, `..` traversal, empty rules ⇒ deny); `classify_porcelain` split; checkpoint behaviour via the pure classifier; `edit_terminal_summary` renders `scope_violation` + branch (mirror test at `:8263`); allowlist validation rejects `../x` and absolute paths.
Live-lab: **no existing stage exercises `ai_edit_run`** (matrix stages are network stages — two_hop, relay, etc.), so no stage proves this today; prove it with one scripted `ai_edit_run` smoke (brief touches `crates/rustynet-cli/src/main.rs`, expect `scope_violation` + attached diff, in-scope files committed), recorded in `documents/operations/active/`.

## Effort

~1.5 days: matcher + validation (2h), hook author/install (3h), checkpoint split + states (4h), tests + smoke + docs (3h).

## Open questions

1. Does OpenCode's config schema support path-scoped `edit` permissions (e.g. `"edit": {"docs/**": "allow", "**": "ask"}`)? Unverifiable here (`https://opencode.ai/config.json` unreachable); layer 1 does not depend on it. If supported, add `**`-deny + allowlist-allow as belt-and-braces.
2. If the owner ran `install.sh`, clone-wide `core.hooksPath` shadows `$GIT_DIR/hooks` — fallback is to add the same positional allowlist check to `scripts/git-hooks/pre-commit` itself; confirm preferred placement.
3. Should `scope_violation` jobs still auto-resume via `base_ref=<branch>` (in-scope commits only), or require explicit relaunch?
