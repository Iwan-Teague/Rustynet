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

## Implementation log

- 2026-09-07 — starting implementation per this plan; worktree `edit-1788775612865-74537-0`, branch `ai-edit/edit-1788775612865-74537-0`. Step 1 next: allowlist constant + pure matchers + unit tests.
- Step 1 done: `DEFAULT_EDIT_PATH_ALLOWLIST` + pure `path_in_allowlist`/`validate_allowlist_rule`/`classify_porcelain` in `ai_agent.rs` (after `EDIT_SESSION_START_GRACE_SECS`), 6 unit tests added; 117/117 pass, fmt clean. Deviation: none. Step 2 next.
- Step 2 done: optional `path_allowlist: string[]` on `ai_edit_run` (validated: relative, non-empty, no `..`; invalid rule or empty array ⇒ call denied; default = the constant), stored as `path_allowlist` in the job record at launch; schema + launch-output line added; test `edit_run_denies_calls_with_invalid_path_allowlist_rules` (6 deny cases). 118/118 pass. Deviation: rules are stored at launch; they are threaded to `create_edit_worktree`/`checkpoint_edit_worktree` in steps 3–4.
- Step 3 done: `create_edit_worktree(job_id, base_ref, rules)` now writes `<worktree>/allowlist.txt`, installs the POSIX-sh pre-commit hook (`EDIT_WORKTREE_PRE_COMMIT_HOOK`) at `<common-git-dir>/worktrees/<job>/hooks/pre-commit` (mode 0755; derives the common dir via `git rev-parse --git-common-dir` in the worktree; refuses A/C/M/R/D staged paths outside the allowlist read positionally via `--show-toplevel`; missing/unreadable allowlist ⇒ exit 1; chains to `scripts/git-hooks/pre-commit` when executable), and adds `allowlist.txt` to the per-worktree `info/exclude` so the guard file never pollutes status/checkpoints. Hook install is fail-closed: any failure fails worktree setup. Hook verified live in a scratch repo (blocks `docs_evil/x.md` naming the path; allows `documents/ok.md`). Deviation: added `info/exclude` (not in plan) so the allowlist file itself is never an out-of-scope checkpoint entry; worktree-setup failure on hook-install error (plan said "fail closed", made explicit).
- Step 4 done: `checkpoint_edit_worktree(worktree, state, rules)` classifies `git status --porcelain` through the same pure `classify_porcelain`, stages + commits ONLY in-scope paths (keep `--no-verify`), leaves out-of-scope paths uncommitted, and returns `(scope_violations, out_of_scope_diff)` (tracked via `git diff -- <paths>`; untracked via per-file-capped `git diff --no-index /dev/null <path>`). `persist_edit_diff` records `scope_violations` + `out_of_scope_diff` + `pre_scope_state` and re-stamps the record into `scope_violation` (never done) when violations exist. Legacy records without a stored allowlist fall back to the default (`rec_allowlist`). Tests: updated the two existing checkpoint tests for the new signature/behaviour and added `checkpoint_never_commits_out_of_allowlist_paths` (the incident, pinned), `persist_edit_diff_stamps_scope_violation_and_never_done`, `rec_allowlist_falls_back_to_the_default_for_legacy_records`. 121/121 pass. Deviation: none beyond the untracked-capture detail the plan already sketched. Step 5 next.
- Step 5 done: `"scope_violation"` added to the terminal arms in `call_edit_result`, `"SCOPE VIOLATION — edits outside the path allowlist"` to the verdict map, `edit_terminal_summary` renders `scope_violations` paths + `out_of_scope_diff` with an explicit "NEVER committed" note and NO auto-resume hint (open question 3 resolved conservatively: relaunch is explicit, never automatic); `ai_edit_result` tool description documents the new state. Tests: `edit_terminal_summary_renders_scope_violations_with_their_diff` + the branch-naming mirror test now covers `scope_violation`. 122/122 pass. Deviation: none. Step 6 next.
- Step 6 done: one advisory sentence appended to both `rustynet-edit-full` and `rustynet-edit-restricted` prompts in `.opencode/opencode.json` (edit only inside the brief's allowlist, named via `allowlist.txt`; out-of-allowlist edits fail the job with `scope_violation`). No permission-map change. JSON validated after edit. Step 7 next.
- Step 7 done: gates green on the pinned 1.88.0 toolchain — `cargo fmt --all -- --check` clean; `cargo clippy -p rustynet-mcp --all-targets --all-features -- -D warnings` clean (one uninlined-format-args lint fixed in a test); `cargo test -p rustynet-mcp --all-targets --all-features` = 282 tests pass across all 5 binaries (25+122+4+110+21). Step 8 next.
- Step 8 done: §12.6 "The four tools" in AGENTS.md + CLAUDE.md now documents the optional `path_allowlist` parameter (default rules, validation, deny-on-invalid, allowlist.txt + hook + checkpoint enforcement) and the `scope_violation` terminal state; `./scripts/ci/check_agents_claude_mirror.sh` passes and `cmp AGENTS.md CLAUDE.md` is silent. Deviations from the Design, all logged above: per-worktree `info/exclude` added so `allowlist.txt` never enters status; hook-install failure fails worktree setup (fail closed made explicit); `scope_violation` jobs get NO auto-resume hint (open question 3 resolved conservatively — relaunch is explicit); open questions 1–2 untouched (layer 1 does not depend on them).

## STATUS 2026-09-07 (UTC — written by the delegated-edit implementation job)

DONE. All 8 plan steps implemented on branch `ai-edit/edit-1788775612865-74537-0`, one commit per step: allowlist matchers + tests (647206f6), `path_allowlist` param (213d6347), worktree allowlist + per-worktree pre-commit hook (31cf0056), scope-aware checkpoint (ce45faeb), `scope_violation` terminal state (523eb44d), opencode prompt advisory (f63be5ff), clippy fix (7e06900c), docs + plan log (3a71d68c and this commit). Gates: fmt clean; `cargo clippy -p rustynet-mcp --all-targets --all-features -- -D warnings` clean; `cargo test -p rustynet-mcp --all-targets --all-features` 282/282 pass; AGENTS/CLAUDE mirror verified. Not done (out of scope for this job, per the plan's Tests section): the scripted live `ai_edit_run` smoke (brief touching `crates/rustynet-cli/src/main.rs`, expecting `scope_violation` + attached diff, in-scope files committed) — it launches a real OpenCode serve and is left to the owner/next session; the classifier and checkpoint behaviour are unit-pinned instead and the hook was verified live in a scratch repo.

- 2026-09-07 — review-fix job opened against DelegatedEditPathGuardReview_2026-09-07 (F1–F7) in worktree `edit-1788780913676-61725-0`, branch `ai-edit/edit-1788780913676-61725-0`. Step R1 next: F3 — parse status via `git status --porcelain=v1 -z` (NUL-split, `dest\0orig` renames) so quoted/non-ASCII paths classify byte-exact.
- Step R1 (F3) done: `classify_porcelain` + the checkpoint's status/untracked-capture now consume `git status --porcelain=v1 -z` (NUL-separated, unquoted; renames as `dest\0orig`); 3 classifier tests updated/added. 123 tests pass. Deviation: none.
- Step R2 (F1 + F7) next: checkpoint resets the index before the scoped add and commits with an explicit pathspec, add/commit/reset failures are loud; `edit_job_diff` diffs `base..HEAD` (F7) because the F1 test pins the branch diff; tests for a pre-staged smuggled file and a staged out-of-scope rename origin.
- Step R2 (F1 + F7) done: `checkpoint_edit_worktree` runs `git reset -q` before the scoped `git add` and commits via `git commit --no-verify -m … -- <in_scope…>`; every reset/add/commit failure is a loud `eprintln!` with git's stderr (no `let _ =`). `edit_job_diff` now diffs `<pinned base>..HEAD`. New tests: `persist_edit_diff_never_commits_a_pre_staged_out_of_scope_file` (branch tip lacks the smuggled path; record lists it), `checkpoint_leaves_a_staged_rename_origin_out_of_scope`. 125 tests pass. Deviation: F7 landed in the same commit as F1 because the F1 test asserts the branch diff.
- Step R3 (F2) next: `pin_worktree_hooks` — enable `extensions.worktreeConfig` on the repo, pin `core.hooksPath` worktree-locally to the job's hooks dir; either failure fails the launch.
- Step R3 (F2) done: `create_edit_worktree` calls `pin_worktree_hooks` (enables `extensions.worktreeConfig` repo-wide once, sets `--worktree core.hooksPath` to the job's hooks dir); any failure fails the launch. Tests: worktree-scoped config asserted after creation (and shown to outrank a simulated install.sh repo-level value); fail-closed error pinned outside a git repo. 127 tests pass. Deviation: none.
- Step R4 (F5 + F6) next: `validate_allowlist_rule` rejects `**` alone (allow-all) and any `\n`/`\r`; single `*` documented as literal.
- Step R4 (F5 + F6) done: validation rejects `**` and newline-bearing rules (matcher doc documents single `*` as literal); deny cases added to the unit test and the end-to-end call-denial test; `single_star_in_a_rule_is_literal_not_a_wildcard` pins the documented semantics. 128 tests pass. Deviation: none.
- Step R5 (F4) next: allowlist-file/hook doc comments and the AGENTS/CLAUDE §12.6 sentence now say the hook defends against accident, not against the agent (the checkpoint is the boundary); mirror check green.
- Step R5 (F4) done: comments + §12.6 sentence updated (also carrying the F5/F6 rule wording); `check_agents_claude_mirror.sh` + `cmp` green.
- Step R6 (gates) next: clippy (`while_let_on_iterator` fix in the untracked-capture loop), then the full scoped test suite.

## Review fixes applied (DelegatedEditPathGuardReview_2026-09-07)

Applied on branch `ai-edit/edit-1788780913676-61725-0`, one commit per step (clippy fix rides with the final docs commit):

- **F1 (BLOCKER)** — `923d9f3b`: `checkpoint_edit_worktree` now runs `git reset -q` (mixed) BEFORE the scoped `git add -- <in_scope…>` and commits via `git commit --no-verify -m <msg> -- <in_scope…>`, so pre-staged out-of-scope index content (including a staged rename's out-of-scope origin) can never reach the branch; reset/add/commit failures are loud `eprintln!`s with git's stderr (no `let _ =`). Tests: `persist_edit_diff_never_commits_a_pre_staged_out_of_scope_file` (staged smuggle + in-scope edit → `git show --name-only` lacks the smuggled path while the record lists it under `scope_violations`), `checkpoint_leaves_a_staged_rename_origin_out_of_scope`.
- **F2** — `6247d0d4`: `pin_worktree_hooks` enables `extensions.worktreeConfig` once on the repo and sets `core.hooksPath` worktree-locally to the job's hooks dir; either failing fails the LAUNCH. Test asserts the worktree-scoped config value after creation (and that it outranks a simulated `install.sh` repo-level value).
- **F3** — `9da51336`: status is read as `git status --porcelain=v1 -z` and split on NUL (renames arrive as `dest\0orig`); quoted/non-ASCII paths are neither dropped nor mangled, unparsable entries stay fail-closed.
- **F4** — `f1c18f23`: the allowlist-file and hook doc comments and the AGENTS.md/CLAUDE.md §12.6 sentence state the hook defends against accident, not against the agent (the checkpoint is the boundary).
- **F5** — `349d59b2`: `validate_allowlist_rule` rejects a rule that is exactly `**` (allow-all); a single `*` is documented as a literal character (`single_star_in_a_rule_is_literal_not_a_wildcard`).
- **F6** — `349d59b2`: rules containing `\n` or `\r` are rejected (the hook's line-delimited allowlist file and the Rust matcher can no longer disagree).
- **F7** — `923d9f3b`: `edit_job_diff` computes the branch diff from `git diff <pinned base>..HEAD`; the terminal summary's "Changes on the branch" no longer shows dirty-worktree content (landed with F1 because the F1 test pins the branch diff).

Gates at the final commit (pinned 1.88.0 toolchain): `cargo fmt --all -- --check` clean; `cargo clippy -p rustynet-mcp --all-targets --all-features -- -D warnings` clean; `cargo test -p rustynet-mcp --all-targets --all-features` = 288 tests pass across all 5 binaries (25+128+4+110+21); `./scripts/ci/check_agents_claude_mirror.sh` + `cmp AGENTS.md CLAUDE.md` silent.

## STATUS 2026-09-07 11:57 UTC (review-fix job, worktree `edit-1788780913676-61725-0`)

DONE. All seven findings of `DelegatedEditPathGuardReview_2026-09-07` applied and committed on branch `ai-edit/edit-1788780913676-61725-0`: F3 `9da51336`, F1+F7 `923d9f3b`, F2 `6247d0d4`, F5+F6 `349d59b2`, F4 `f1c18f23`, gates + this section in the final commit. Gates: fmt clean; scoped clippy clean; 288/288 `rustynet-mcp` tests pass; AGENTS/CLAUDE mirror verified. Not done (unchanged from the plan's own STATUS): the scripted live `ai_edit_run` smoke and the Open questions (1–3) — out of scope for this job. Next: human review + merge of this branch; open questions remain owner decisions.

## Open questions

1. Does OpenCode's config schema support path-scoped `edit` permissions (e.g. `"edit": {"docs/**": "allow", "**": "ask"}`)? Unverifiable here (`https://opencode.ai/config.json` unreachable); layer 1 does not depend on it. If supported, add `**`-deny + allowlist-allow as belt-and-braces.
2. If the owner ran `install.sh`, clone-wide `core.hooksPath` shadows `$GIT_DIR/hooks` — fallback is to add the same positional allowlist check to `scripts/git-hooks/pre-commit` itself; confirm preferred placement.
3. Should `scope_violation` jobs still auto-resume via `base_ref=<branch>` (in-scope commits only), or require explicit relaunch?
