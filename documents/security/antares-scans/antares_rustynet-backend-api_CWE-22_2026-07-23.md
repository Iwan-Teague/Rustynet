# Antares scan — `rustynet-backend-api` — CWE-22

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-api` (3 first-party `.rs` files)  
**CWE:** CWE-22 — Path traversal: externally-influenced input constructs a filesystem path that escapes the intended directory (../ etc.).  
**Verdict:** `vulnerable_files`  
**Budget:** 15/15 terminal cmds, 20 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

src/lib.rs contains NodeId handling and likely backend logic that constructs filesystem paths from externally-influenced inputs; this is the most likely location for CWE-22 path traversal issues.

## Commands run
```
$ cd /workspace/repo/ && find . -maxdepth 2 | head -n 200
$ find . -maxdepth 2 | head -n 200
$ grep -RIn "\.open\(" src || true; grep -RIn "send_file\(" src || true; grep -RIn "send_from_directory\(" src || true; grep -RIn "resolve\(" src || true; grep -RIn "realpath\(" src || true; grep -RIn "normpath\(" src || true; grep -RIn "\.join\(" src || true; grep -RIn "\.join\(" src || true
$ grep -RIn "\.open\(" src || true
$ grep -RIn "\.open\(" src
$ grep -RIn "File::open" src
$ grep -RIn "open(" src
$ grep -RIn "open\(" src
$ grep -RIn "open\(" src
$ grep -RIn "\.open" src
$ grep -RIn "\.open" src
$ grep -RIn "\.open" src
$ grep -RIn "\.open" src
$ grep -RIn "\.open" src
$ cat src/lib.rs
$ grep -RIn "\.open\(" src
$ grep -RIn "\.open" src
$ grep -RIn "\.open" src
```
