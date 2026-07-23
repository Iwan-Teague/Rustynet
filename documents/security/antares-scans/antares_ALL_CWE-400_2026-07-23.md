# Antares scan — `ALL` — CWE-400

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-400 — Uncontrolled resource consumption: resources (CPU, memory, connections, buffers) are not bounded, enabling resource-exhaustion / DoS.  
**Verdict:** `error`  
**Budget:** 10/30 terminal cmds, 18 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

HTTP 500: {"error":{"code":500,"message":"Failed to parse tool call arguments as JSON: [json.exception.parse_error.101] parse error at line 1, column 1812: syntax error while parsing value - invalid string: missing closing quote; last read: '\"The repository contains multiple places that use fs::read_to_string() to read entire files into memory. This can lead to uncontrolled memory consumption if attacker-controlled files are present (symlinks, in-place growth, or crafted files). The vulnerable locations include crates/rustynetd/src/* and other CLI/daemon modules that read configuration or bundle files into memory. These reads'","type":"server_error"}}

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "read_line\|lines().for_chunk\|read_to_string\|read_to_end\|Vec::with_capacity\|Vec::reserve\|Vec::with_capacity\|Vec::new\|loop\|spawn\|tokio::spawn\|spawn_future\|spawn\(|thread::spawn\|TcpStream::connect\|TcpStream::new\|UdpSocket::new\(|UdpSocket::try_bound\|accept\(" /workspace/repo/crates | head -n 200
$ grep -RIn "read_line" /workspace/repo/crates | head -n 200
$ grep -RIn "lines()\.\|read_to_string\|read_to_end\|Vec::with_capacity\|reserve\|with_capacity\|new\(\}\u5f96\b\|loop\|spawn\(|thread::spawn\(" /workspace/repo/crates | head -n 300
$ grep -RIn "lines()\." /workspace/repo/crates | head -n 300
$ grep -RIn "read_line(" /workspace/repo | head -n 200
$ grep -RIn "lines()\.\.\|lines()\.\|lines()\(.)\.\|lines().collect()\.\.\"\.|lines().collect()\.\.\"\"" /workspace/repo/crates | head -n 200
$ grep -RIn "lines().collect()\." /workspace/repo/crates | head -n 200
$ grep -RIn "read_to_string" /workspace/repo/crates | head -n 200
$ grep -RIn "lines().collect()\.\.\.|lines().collect_()\.\.\.|lines().collect_()\.\.\"" /workspace/repo/crates/rustynetd | head -n 200
$ grep -RIn "lines().collect()\." /workspace/repo/crates | head -n 200
$ grep -RIn "read_to_string(" /workspace/repo/crates | head -n 200
$ grep -RIn "read_to_string(" /workspace/repo/gui | head -n 200
$ sed -n '1220,1280p' /workspace/repo/gui/node-map-tool/src/main.rs
```
