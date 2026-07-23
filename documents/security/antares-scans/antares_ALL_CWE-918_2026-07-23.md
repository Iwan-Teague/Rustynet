# Antares scan — `ALL` — CWE-918

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-918 — Server-side request forgery: server can be induced to make requests to an unintended destination.  
**Verdict:** `vulnerable_files`  
**Budget:** 12/30 terminal cmds, 13 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynetd/src/daemon.rs` | inspected |

## Model reasoning

The vulnerable code is in crates/rustynetd/src/daemon.rs. The `http_get_raw` function (around line 454) parses and fetches remote HTTP content using `Tcp::new(&url)` and then reads the response into memory. This creates a network connection to the provided URL, which can be an external destination. The function only checks that the URL starts with 'http://' but does not validate the hostname or enforce connection restrictions, allowing server-side request forgery (CWE-918) if an attacker can induce the server to make requests to unintended destinations.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "http" /workspace/repo/crates | head -n 200
$ grep -RIn "http_get" /workspace/repo/crates | head -n 200
$ cat /workspace/repo/crates/rustynetd/src/daemon.rs | head -n 500
$ sed -n '440,470p' /workspace/repo/crates/rustynetd/src/daemon.rs
$ grep -RIn "http_get_raw" /workspace/repo/crates | head -n 200
$ grep -RIn "Tcp::new" /workspace/repo/crates | head -n 200
$ grep -RIn "http_get_raw\." /workspace/repo/crates | head -n 200
$ grep -RIn "http_get_raw\)\." /workspace/repo/crates | head -n 200
$ grep -RIn "http_get_raw\." /workspace/repo/crates | head -n 200
$ grep -RIn "http_get_raw" /workspace/repo/crates | tail -n 200
```
