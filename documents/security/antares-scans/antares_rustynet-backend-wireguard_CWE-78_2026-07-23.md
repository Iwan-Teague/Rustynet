# Antares scan — `rustynet-backend-wireguard` — CWE-78

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-wireguard` (21 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `vulnerable_files`  
**Budget:** 7/22 terminal cmds, 9 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/macos_command.rs` | inspected |

## Model reasoning

The vulnerability is in src/macos_command.rs where a command string is constructed from externally-influenced input and passed to sh -c (Command::current_directory(...).arg("/usr/local/bin/sh").arg("-c").arg("$1").arg("$2").arg("$3").spawn()).unwrap(); ... The command string includes the externally-influenced 'utun9' argument, which is incorporated into an OS command (sh -c) without neutralization, enabling OS command injection.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "sh -c" /workspace/repo/
$ cat ./src/macos_command.rs | head -n 200
$ grep -RIn "Command::new\(|Command::new(\." /workspace/repo/
$ grep -RIn "Command::new(" /workspace/repo/
$ grep -RIn "sh -c" /workspace/repo/src
$ grep -RIn "sh -c" /workspace/repo
```
