# Antares scan — `rustynet-crypto` — CWE-22

**Date:** 2026-07-23  
**Scope:** `rustynet-crypto` (1 first-party `.rs` files)  
**CWE:** CWE-22 — Path traversal: externally-influenced input constructs a filesystem path that escapes the intended directory (../ etc.).  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 13 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The implementation opens filesystem paths from user-supplied candidates (e.g., SecKeychain::open, other open calls) using std::fs::File::open and related APIs. These constructs can construct paths from externally-influenced input and may not validate traversal characters (../), so an attacker-controlled path could escape the intended directory. The relevant call sites are in src/lib.rs.

## Commands run
```
$ grep -RIn "os\.path\.join\|os\.path\.realpath\|os\.path\.normpath\|\.\.\/\|../\|path traversal\|send_from_directory\|send_file\|join(" /workspace/repo/*
$ grep -RIn "os\.path\.join\|os\.path\.realpath\|os\.path\.normpath\|\.\.\/\|../\|path traversal\|send_from_directory\|send_file\|join\(" /workspace/repo/
$ grep -RIn "os\.path\.join" /workspace/repo/
$ grep -RIn "send_from_directory" /workspace/repo/
$ grep -RIn "send_file" /workspace/repo/
$ grep -RIn "os\.path\.realpath" /workspace/repo/
$ grep -RIn "os\.path\.normpath" /workspace/repo/
$ find . -maxdepth 2 | head -n 200
$ cat /workspace/repo/src/lib.rs
$ grep -RIn "open\.|File::open\|std::fs::" /workspace/repo/src/lib.rs
$ grep -RIn "open\.|File::open\|std::fs::" /workspace/repo/src/lib.rs
$ grep -RIn "open\b" /workspace/repo/src/lib.rs
```
