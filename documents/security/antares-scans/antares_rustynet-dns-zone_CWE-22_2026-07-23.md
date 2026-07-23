# Antares scan — `rustynet-dns-zone` — CWE-22

**Date:** 2026-07-23  
**Scope:** `rustynet-dns-zone` (1 first-party `.rs` files)  
**CWE:** CWE-22 — Path traversal: externally-influenced input constructs a filesystem path that escapes the intended directory (../ etc.).  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 14 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The DNS zone verification implementation in src/lib.rs parses zone bundle payloads and canonicalizes names; if bundle loading or reading bundle files from disk is implemented elsewhere, it could construct filesystem paths from externally-influenced bundle filenames and use path traversal characters (../) to access unintended files. The inspected lib.rs shows name canonicalization logic but does not reveal filesystem path traversal in the visible code.

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
$ grep -RIn "open\(|File::open\(|read_to_string\(|read_to_owned\(" /workspace/repo/src/
$ grep -RIn "File::open(" /workspace/repo/src/
```
