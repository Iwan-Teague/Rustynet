# Antares scan — `rustynet-backend-wireguard` — CWE-22

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-wireguard` (21 first-party `.rs` files)  
**CWE:** CWE-22 — Path traversal: externally-influenced input constructs a filesystem path that escapes the intended directory (../ etc.).  
**Verdict:** `aborted`  
**Budget:** 5/22 terminal cmds, 10 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

model produced 3 consecutive turns with no tool call

## Commands run
```
$ cd /workspace/repo/ && ls
$ find . -maxdepth 2 | head -n 200
$ grep -RIn "\.\.\/\|\.\/\.\|\.\/\.\/\|join\(" src || true
$ grep -RIn "\.\.\/" src
$ grep -RIn "join\(" src | head -n 200
$ grep -RIn "join\(" src
$ grep -RIn "open\(" src | head -n 200
```
