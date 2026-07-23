# Antares scan — `ALL` — CWE-22

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-22 — Path traversal: externally-influenced input constructs a filesystem path that escapes the intended directory (../ etc.).  
**Verdict:** `vulnerable_files`  
**Budget:** 20/30 terminal cmds, 25 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynetd/src/privileged_helper.rs` | inferred (grep-only) |

## Model reasoning

The file crates/rustynetd/src/privileged_helper.rs contains fs::canonicalize(path) calls that may operate on paths influenced by external input. fs::canonicalize without explicit containment checks can resolve '..' segments and potentially escape intended directories, matching CWE-22 path traversal concerns.

## Commands run
```
$ ls
$ grep -RIn "\.\./\|../\|canonicalize\|canonicalize_abs\|Path::join\|join(" .
$ grep -RIn "canonicalize" .
$ grep -RIn "canonicalize(" crates | grep -E "rustynetd|rustynet-dns-zone|rustynet-cli|rustynet-lab-monitor|gui|tools"
$ grep -RIn "fs::canonicalize(" crates | grep -E "rustynetd|rustynet-dns-zone|rustynet-cli|rustynet-lab-monitor|gui|tools"
$ grep -RIn "fs::canonicalize(" rustynetd
$ grep -RIn "canonicalize_dns_relative_name" crates | head -n 200
$ grep -RIn "Path::join\(" crates | head -n 200
$ grep -RIn "Path::join" crates
$ grep -RIn "join(" crates
$ grep -RIn "Path::join(" crates/rustynetd crates/rustynet-dns-zone crates/rustynet-cli crates/rustynet-lab-monitor crates/gui crates/tools
$ grep -RIn "Path::join(" crates/rustynet-dns-zone/src
$ grep -RIn "join(" crates/rustynet-dns-zone/src
$ grep -RIn "canonicalize_dns_zone_name" crates/rustynet-dns-zone/src
$ grep -RIn "canonicalize" rustynetd | grep -E "canonicalize_dns_zone_name|canonicalize_dns_zone_fqdn|canonicalize_dns_zone_name\("
$ grep -RIn "canonicalize" rustynetd
$ grep -RIn "canonicalize" crates/rustynet-dns-zone/src
$ grep -RIn "fs::canonicalize" crates
$ grep -RIn "canonicalize\(" crates/rustynetd crates/rustynet-dns-zone crates/rustynet-cli crates/rustynet-lab-monitor crates/gui crates/tools
$ grep -RIn "canonicalize" crates/rustynetd crates/rustynet-dns-zone crates/rustynet-cli crates/rustynet-lab-monitor crates/gui crates/tools
$ grep -RIn "canonicalize\(" crates/rustynetd crates/rustynet-dns-zone crates/rustynet-cli crates/rustynet-lab-monitor crates/gui crates/tools
$ grep -RIn "canonicalize" crates/rustynetd crates/rustynet-dns-zone crates/rustynet-cli crates/rustynet-lab-monitor crates/gui crates/tools
$ grep -RIn "canonicalize\(" crates/rustynetd crates/rustynet-dns-zone crates/rustynet-cli crates/rustynet-lab-monitor crates/gui crates/tools
$ grep -RIn "canonicalize" crates/rustynetd crates/rustynet-dns-zone crates/rustynet-cli crates/rustynet-lab-monitor crates/gui crates/tools
```
