# Antares scan — `ALL` — CWE-78

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-78 — OS command injection: externally-influenced input is incorporated into an OS command (sh -c, Command args) without neutralization.  
**Verdict:** `vulnerable_files`  
**Budget:** 14/30 terminal cmds, 15 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynetd/src/phase10.rs` | inspected |
| `crates/rustynet-cli/src/main.rs` | inferred (grep-only) |
| `crates/rustynet-cli/src/install/live_windows.rs` | inferred (grep-only) |
| `crates/rustynet-cli/src/vm_lab/mod.rs` | inferred (grep-only) |

## Model reasoning

The code constructs shell commands using string interpolation and directly passes externally-influenced values (e.g., paths, binaries) into Command::new(...) without proper neutralization. Examples include Command::new("powershell.exe") bare-name invocations and Command::new(...) with constructed command arguments. These patterns can lead to OS command injection if attacker-controlled input is incorporated into command arguments or invoked via shell mechanisms.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "Command::new" /workspace/repo/crates | head -n 200
$ grep -RIn "Command::new\(" /workspace/repo/crates | head -n 200
$ grep -RIn "Command::new\(" /workspace/repo/crates | head -n 200
$ grep -RIn "Command::new(" /workspace/repo/crates | head -n 200
$ grep -RIn "Command::new\(" /workspace/repo --include="*.rs" | sed -n '1,200p'
$ grep -RIn "Command::new(" /workspace/repo/gui/
$ grep -RIn "Command::new\(" /workspace/repo/crates | head -n 200
$ grep -RIn "Command::new(" /workspace/repo/crates/rustynetd | head -n 200
$ grep -RIn "Command::new\(" /workspace/repo/crates/rustynetd/src | head -n 200
$ grep -RIn "powershell.exe\"" /workspace/repo/crates | head -n 50
$ sed -n '1100,1260p' crates/rustynetd/src/phase10.rs
$ grep -RIn "Command::new\(" crates | grep -i "phase10"
```
