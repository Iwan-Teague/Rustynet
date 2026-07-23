# Antares scan — `rustynet-control` — CWE-22

**Date:** 2026-07-23  
**Scope:** `rustynet-control` (16 first-party `.rs` files)  
**CWE:** CWE-22 — Path traversal: externally-influenced input constructs a filesystem path that escapes the intended directory (../ etc.).  
**Verdict:** `vulnerable_files`  
**Budget:** 11/22 terminal cmds, 18 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/persistence.rs` | inspected |

## Model reasoning

The file uses include_str!(../migrations/0001_init.sql) inside .execute_batch(), constructing a filesystem path from an externally-influenced string. The ../ escapes the intended migrations directory, enabling path traversal (CWE-22).

## Commands run
```
$ cd /workspace/repo/ && ls
$ find . -maxdepth 2 | head -n 200
$ grep -RIn "\.\.\/\|\.\/\.\|\.\/\.\/\|join\(" src
$ grep -RIn "\.\/\." src
$ grep -RIn "\.\.\/" src
$ grep -RIn "include_path\|include_path!\|include_path" src
$ grep -RIn "include_path" src
$ grep -RIn "include_path" .
$ grep -RIn "\.\/\." .
$ grep -RIn "\.\.\/" .
$ cat src/persistence.rs
$ grep -n "include_str\!\(" src/persistence.rs
$ grep -n "include_str" src/persistence.rs
$ grep -RIn "execute_batch\(" src
$ grep -RIn "execute_batch" src
$ grep -n "0001_init.sql" src/persistence.rs
```
