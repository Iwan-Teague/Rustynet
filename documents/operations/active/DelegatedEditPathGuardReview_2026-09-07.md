# Delegated-Edit Path Guard — Adversarial Review (2026-09-07)

Scope reviewed: `git diff 1efc8376..HEAD -- crates/ .opencode/ scripts/`
(`crates/rustynet-mcp/src/bin/ai_agent.rs`, `.opencode/opencode.json` prompt
additions; no `scripts/` changes in range). The full-range diff also touches
`AGENTS.md`/`CLAUDE.md` (mirror sync of the §12.6 tool description) — expected
per the docs-sync mandate, not a scope violation. The only shipped-code file
touched is `ai_agent.rs`, matching the intended area.

Method: read the diff plus surrounding code; line numbers are HEAD
(`79d68e4f`). Answers to the specific questions asked are inline.

---

## Findings

### F1 — BLOCKER: `checkpoint_edit_worktree` commits the whole index, so a PRE-STAGED out-of-scope edit still reaches the branch

`crates/rustynet-mcp/src/bin/ai_agent.rs:3591` stages only `in_scope`
(`git add -- <in_scope>`), but the commit at `ai_agent.rs:3601`
(`git commit --no-verify -m &msg`) commits the **entire index**, which may
already hold out-of-scope entries the agent staged itself before the job
ended (e.g. its own `git add -A` cut off by the budget watchdog, or a
`restricted`-mode change the agent staged between approval polls).

Failure scenario: agent runs `git add crates/rustynet-cli/src/main.rs`
(out of the default allowlist) and also edits `documents/x.md`, then is
halted. `classify_porcelain` correctly returns `in_scope=[documents/x.md]`,
`out_scope=[crates/rustynet-cli/src/main.rs]`; the server adds the in-scope
file and commits — the index still carries `main.rs`, so the smuggled edit
lands on `ai-edit/<job_id>` **and** the record simultaneously reports
`scope_violations` containing it. The summary then contradicts itself: the
violations section says "NEVER committed to the branch" (`ai_agent.rs:3766`)
while the branch diff shows it. This is exactly the 2026-09-07 incident shape
(`crates/rustynet-cli/src/main.rs` smuggled by an auto-checkpoint) that this
guard exists to close, reopened through a different door.

Same mechanism for the rename case the tests pin: a staged rename
` R old.txt -> documents/new.txt` (`ai_agent.rs:8708-8727` asserts
`old.txt` is out-of-scope) is committed wholesale via the index — the
out-of-scope origin's deletion rides along, so the test's "checked on BOTH
sides" contract is classified but never enforced at commit time.

Fix (one line): unstage everything before the scoped add —
`git reset -q` (mixed) before `git add -- <in_scope>` — or better, use a
pathspec commit `git commit --no-verify -m msg -- <in_scope…>` which builds
the commit from HEAD + only the named paths.

Test gap that hid it: `persist_edit_diff_stamps_scope_violation_and_never_done`
(`ai_agent.rs:9048`) only exercises an **untracked** smuggled file. Add a case
where the out-of-scope file is **staged** (`git add smuggled.txt` before
`persist_edit_diff`) plus one in-scope edit, and assert
`git show --name-only` on the resulting branch does not contain `smuggled.txt`.
Today that assertion would fail — the test that exists passes for the wrong
reason (classifier-only).

### F2 — SHOULD-FIX: `core.hooksPath` shadows the per-worktree hook on every clone that ran `scripts/git-hooks/install.sh`

Verified on this clone: `git config --get core.hooksPath` →
`scripts/git-hooks`, set by `scripts/git-hooks/install.sh:11`
(`git -C "$root" config core.hooksPath scripts/git-hooks`). Repo-level
config is shared by linked worktrees, so on any machine where the hooks are
installed, the per-worktree hook written to
`$GIT_COMMON_DIR/worktrees/<job>/hooks/pre-commit`
(`ai_agent.rs:2503-2504`) **never executes** — git consults
`core.hooksPath` first. The doc comment at `ai_agent.rs:482` ("linked
worktrees consult their own `$GIT_DIR/hooks` when `core.hooksPath` is
unset") is only true on clones that skipped `install.sh`. Hook-install
failures themselves ARE fatal (`create_edit_worktree` returns
`Err` on write/chmod failure, `ai_agent.rs:2504-2511` — answered: fatal,
fail-closed), but shadowing is a silent no-op the code cannot see.

Severity: should-fix only because the doc comment explicitly declares this
layer "defence in depth" with `checkpoint_edit_worktree` as the real
boundary — but a second layer that is inert on configured machines is not a
layer, and nothing records that it didn't run.

Fix: after creating the worktree, run
`git config extensions.worktreeConfig true` once in the repo and
`git config --worktree core.hooksPath <per-worktree hooks dir>` in the new
worktree (or, at minimum, detect an active `core.hooksPath` at setup and
fail the launch loudly instead of installing a hook that cannot fire).

### F3 — SHOULD-FIX: porcelain quoting is stripped, not unescaped — in-scope non-ASCII/quoted-named files are silently dropped from the checkpoint

`classify_porcelain` (`ai_agent.rs:663-664`) only strips the surrounding
quotes of porcelain C-style quoting; the inner escapes
(`\320\264…` octal for non-ASCII under default `core.quotePath`, `\"`,
`\\`) are left intact. Consequences, two directions:

1. In-scope file `documents/док.md` is staged as the literal escaped string
   `documents/\320\264\320\276\320\272.md` → `git add` fails **silently**
   (`let _ = run_with_timeout(...)`, `ai_agent.rs:3592-3595`). If that is
   the only change, the subsequent `git commit` finds nothing to commit and
   also fails silently — the branch is missing in-scope work the record's
   own diff section still advertises. Work loss on the deliverable branch,
   silent.
2. Out-of-scope exotic-named files are recorded as violations with their
   escaped names — fail-closed, no security impact, but the human reviewer
   gets `\320\264` gibberish instead of the path (and `git diff -- <escaped>`
   captures no diff, `ai_agent.rs:3607-3612`).

Fix: read status with `-z` (`git status --porcelain=v1 -z`) and split on
NUL — unquoted, no escaping layer at all, and the rename pair
`orig\0dest\0` drops the ` -> ` parsing entirely. (Answered: the `-z`-less
hook at `ai_agent.rs:530` uses `tr '\0' '\n'`, which splits a
newline-containing filename into fragments that then DENY — fail-closed,
acceptable for the defence-in-depth layer.)

### F4 — NIT: `allowlist.txt` is agent-writable, so the hook guard is neutralizable

The hook reads `$ROOT/allowlist.txt` (`ai_agent.rs:489-537` section) at
commit time; the agent has `bash: allow` and the file sits writable at the
worktree root, so it can append `crates/**` and commit anything. The comment
at `ai_agent.rs:480-481` claims positional reading means "an agent cannot
point the guard at a different file" — true, but it can rewrite *this* file.
No privilege change (checkpoint is the real boundary and reads the immutable
launch record via `rec_allowlist`, `ai_agent.rs:683-695`), but the
"fail closed … positional" framing overstates what the hook defends. Fix:
one sentence in the comment (and the AGENTS.md §12.6 description) stating
the hook defends against accident, not against the agent.

### F5 — NIT: rule validation permits `**` alone (allow-all) and treats single `*` literally

`validate_allowlist_rule` (`ai_agent.rs:624-637`) rejects empty, absolute,
and `..` — but `["**"]` passes and matches every path (empty prefix + empty
suffix at `ai_agent.rs:607-611`): the driving agent, the very actor this
guard exists to constrain, can opt itself into allow-all with one
explicit-looking rule. There is no audit trail beyond the record's
`path_allowlist` field. Separately, `documents/*.md` contains no `**`, so it
matches only a path literally spelled `documents/*.md` — silent divergence
from the "gitignore-style rules" wording in the tool schema
(`ai_agent.rs:8650-8651`). Fix: reject a rule that is exactly `**` (or
require caller confirmation), and either document single-`*`-is-literal or
reject bare `*`.

### F6 — NIT: rule strings may contain embedded newlines — hook and Rust matcher then disagree

A rule like `"documents/**\ncrates/**"` passes validation (trim doesn't
remove interior `\n`), is stored as one rule the Rust matcher can never
match (deny — fine), but `format!("{}\n", rules.join("\n"))`
(`ai_agent.rs:2473-2475`) writes it as **two** hook rules the shell matcher
will happily allow. Net still fail-closed (the checkpoint denies what the
hook allows), but the two layers disagree for no reason. Fix: reject `\n`
(and `\r`) in `validate_allowlist_rule`.

### F7 — NIT: terminal summary can show out-of-scope diffs under "Changes on the branch"

`edit_job_diff` is `git diff <base_ref>` over the worktree
(`ai_agent.rs:2816-2828`), which includes **uncommitted** out-of-scope
edits; `edit_terminal_summary` prints it under "Changes on the branch:"
(`ai_agent.rs:3785-3787`) directly after a violations section asserting
those same edits "NEVER committed". Misleading, not a commit-path hole.
Fix: compute the branch diff from the branch tip (`git diff
<base_ref>..<HEAD>` in the worktree) instead of the dirty worktree.

---

## Answers to the specific review questions

- **Can an out-of-allowlist edit still reach the branch?** Yes — F1
  (pre-staged index content commits wholesale; staged rename origins ride
  along). All other vectors close: symlinks are stored as links, not
  followed; `..` components deny in both matchers (`ai_agent.rs:600-602`,
  hook's `*/../*|*/..|../*|..` case); absolute paths can't occur in
  repo-relative porcelain; the `documents` vs `documents_evil` boundary is
  correct in both matchers (`ai_agent.rs:612-614`, hook's `"$rule"|"$rule"/*`).
- **Can a violation read as `done`?** No — `persist_edit_diff` re-stamps
  `scope_violation` unconditionally when violations exist
  (`ai_agent.rs:3678-3683`), records `pre_scope_state`, and
  `ai_edit_result` treats `scope_violation` as a distinct terminal state
  (`ai_agent.rs:3193`). A scope violation is never reported `done`.
- **Are hook-install failures fatal?** Yes — `create_edit_worktree` fails
  the launch on any write/chmod error (`ai_agent.rs:2497-2511`). But F2:
  shadowing by `core.hooksPath` is a silent no-op.
- **Is any shell built from rule strings?** No. Rules are written only to
  `allowlist.txt` (`ai_agent.rs:2473`) and echoed into the static hook
  constant; the hook is fixed text. All `run_with_timeout` git invocations
  pass paths as separate argv entries — no shell construction anywhere in
  the diff.
- **`core.hooksPath` shadowing?** Yes, real — F2 (verified live on this
  clone).
- **Empty/malformed allowlist?** Empty array denied at launch
  (`ai_agent.rs:2940-2944`), empty rules deny every path in the matcher
  (`ai_agent.rs:8692-8694`), missing/unreadable `allowlist.txt` refuses the
  hook commit, legacy records fall back to the default list
  (`ai_agent.rs:683-695`). Solid. Only F6's newline rule diverges the two
  layers.
- **unwrap/expect/panic in non-test code?** None added; quote-stripping uses
  `strip_prefix(...).unwrap_or(...)`, indexing uses `line.get(3..)`.
- **Scope?** Clean — `ai_agent.rs` + the two agent prompts in
  `.opencode/opencode.json` (the allowlist sentence) + mirrored
  AGENTS/CLAUDE text + the plan document. No `scripts/` or crate changes
  beyond the MCP server.

## Test gaps

- No test that a **staged** out-of-scope file stays off the branch (F1) —
  the existing integration-style test uses an untracked file only.
- No test for quoted/escaped porcelain names against `classify_porcelain`
  (F3) — the escaped form would currently be matched as-is.
- No test (or runtime detection) for the `core.hooksPath` shadowing
  configuration (F2).

---

VERDICT: MERGE-WITH-FIXES — F1 lets a pre-staged out-of-scope edit land on the
deliverable branch while the record claims it never left the worktree, which
reopens the exact smuggling path this guard was built to close.

## Disposition (fix job edit-1788780913676-61725-0, verified by the managing session)

- F1 — FIXED (923d9f3b): the checkpoint mixed-resets the index, re-stages only in-scope paths, and commits with an explicit pathspec; a `reset`/`add` failure aborts without committing; test `persist_edit_diff_never_commits_a_pre_staged_out_of_scope_file`.
- F2 — FIXED (6247d0d4): `core.hooksPath` is pinned worktree-locally to the job's hooks dir at worktree creation; failure to pin is a hard error.
- F3 — FIXED (9da51336): `git status --porcelain=v1 -z`, byte-exact classification of quoted and non-ASCII paths.
- F4 — DOCUMENTED (f1c18f23): the hook guards against accident, not the agent; the programmatic checkpoint is the enforcement point.
- F5/F6 — FIXED (349d59b2): allow-all (`**`) and multi-line rules are rejected; single `*` is literal by documented semantics.
- F7 — FIXED (923d9f3b): the terminal summary diffs the branch, not the worktree.
