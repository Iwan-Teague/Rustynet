# Antares scan — `rustynet-dns-zone` — CWE-78

**Date:** 2026-07-23  
**Scope:** `rustynet-dns-zone` (1 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `aborted`  
**Budget:** 5/8 terminal cmds, 13 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

model produced 3 consecutive turns with no tool call

## Commands run
```
$ ls
$ find . -maxdepth 2 | grep -E "src|Cargo\.toml"
$ find src -maxdepth 2 | grep -E "\.sh|\.py|\.js|\.ts"
$ grep -RIn "sh -c\|/bin/sh\|/bin/bash\|system\(|exec\(|popen\(|spawn\(" src
$ grep -RIn "sh -c\|/bin/sh\|/bin/bash\|system\(" src
$ grep -RIn "sh -c" src
$ grep -RIn "system\(" src
$ grep -RIn "popen\(" src
$ grep -RIn "\.exe\b" src
```
