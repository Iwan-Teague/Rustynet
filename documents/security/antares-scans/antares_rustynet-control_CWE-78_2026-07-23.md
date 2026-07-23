# Antares scan — `rustynet-control` — CWE-78

**Date:** 2026-07-23  
**Scope:** `rustynet-control` (16 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `vulnerable_files`  
**Budget:** 6/22 terminal cmds, 8 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/admin.rs` | inferred (grep-only) |
| `src/credential_unwrap.rs` | inspected |

## Model reasoning

The process constructs OS commands using externally-influenced input (privileged commands and helper programs) without using an argv-only invocation pattern. In src/admin.rs, PrivilegedCommand::validate_privileged_command() accepts a command path and Command::new(...) is used to spawn it. In src/credential_unwrap.rs, run_helper_and_capture() spawns a helper program and passes argv values to it. Both call Command::new(...) with string arguments derived from caller input, which can lead to OS command injection if the input is not properly sanitized. The code includes comments warning about using argv-only invocation to mitigate shell construction, but the actual implementation uses Command::new(...) with string args, enabling command injection.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 100
$ grep -RIn "sh -c" /workspace/repo/
$ grep -RIn "spawn(" /workspace/repo/
$ grep -RIn "Command" /workspace/repo/
$ sed -n '470,540p' /workspace/repo/src/credential_unwrap.rs
$ grep -RIn "Command::new\(|Command::new(\.|args\(" /workspace/repo/
```
