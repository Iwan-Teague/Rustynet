# Antares scan — `rustynet-backend-stub` — CWE-78

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-stub` (2 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 17 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inferred (grep-only) |

## Model reasoning

The repository is a Rust project with limited source files; command-injection via shell sh -c or bash invocation patterns were not found. The most likely location for OS command injection would be in a backend implementation, but no such implementation or shell-command-execution code was located in the inspected files.

## Commands run
```
$ ls
$ grep -RIn "Command::new\(" src
$ grep -RIn "Command::new" src
$ grep -RIn "sh -c\|bash -c\|/bin/sh\|/bin/sh -c" src
$ grep -RIn "sh" src
$ find . -maxdepth 2 | grep -E "src|Cargo\.toml"
$ find src -maxdepth 2 | head -n 200
$ find . -type d | grep -E "src|lib|backend|config"
$ find . -maxdepth 2 | grep -E "\.sh\|\.cmd\|\.bat\|exe\|bin"
$ grep -RIn "\`" src
$ grep -RIn "/bin/sh" src
$ grep -RIn "sh" src
$ grep -RIn "tokio::process\|std::process\|sh -c\|bash -c\|spawn\(" src
$ grep -RIn "tokio::process" src
```
