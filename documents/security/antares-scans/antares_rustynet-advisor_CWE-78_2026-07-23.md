# Antares scan — `rustynet-advisor` — CWE-78

**Date:** 2026-07-23  
**Scope:** `rustynet-advisor` (2 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `aborted`  
**Budget:** 6/8 terminal cmds, 12 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

model produced 3 consecutive turns with no tool call

## Commands run
```
$ ls
$ grep -RIn "Command::new\(" src
$ rg -n "Command::new\(" src
$ grep -RIn "spawn\(" src
$ grep -RIn "\.exe\.|std::process::Command\|Command::new\|std::process::Command\?\(" src
$ grep -RIn "std::process" src
$ grep -RIn "std::process" Cargo.toml
```
