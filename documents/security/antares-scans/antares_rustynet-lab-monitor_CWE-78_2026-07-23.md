# Antares scan — `rustynet-lab-monitor` — CWE-78

**Date:** 2026-07-23  
**Scope:** `rustynet-lab-monitor` (34 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `vulnerable_files`  
**Budget:** 13/22 terminal cmds, 15 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/data/job_watcher.rs` | inspected |

## Model reasoning

The vulnerability is in src/data/job_watcher.rs at line 330: `let output = std::process::Command::new("ps")`. The `ps` command is called with `std::process::Command::new("ps")` and the resulting process is used to extract orchestrator process information. This is an OS command injection risk if the command arguments are externally influenced (e.g., via `--report-dir` or other CLI input) and are not properly sanitized before being incorporated into the command invocation.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 100
$ grep -RIn "CommandFactory\|CommandFactory::new\|sh -c\|spawn_exe\|std::process::Command\|Command::new\|exec(\"\|system(\"" /workspace/repo/
$ grep -RIn "CommandFactory" /workspace/repo/
$ grep -RIn "Command::new" /workspace/repo/
$ grep -RIn "Command::new(" /workspace/repo/
$ grep -RIn "std::process::" /workspace/repo/
$ grep -RIn "sh -c" /workspace/repo/
$ grep -RIn "Command::new\+\"" /workspace/repo/
$ cat src/data/job_watcher.rs | head -n 100
$ grep -RIn "Command::new\(" src/data/job_watcher.rs
$ grep -RIn "Command::new(" src/data/job_watcher.rs
$ sed -n '320,350p' src/data/job_watcher.rs
$ grep -RIn "sh -c" .
```
