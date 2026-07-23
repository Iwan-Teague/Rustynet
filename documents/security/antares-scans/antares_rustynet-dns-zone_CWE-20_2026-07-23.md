# Antares scan — `rustynet-dns-zone` — CWE-20

**Date:** 2026-07-23  
**Scope:** `rustynet-dns-zone` (1 first-party `.rs` files)  
**CWE:** CWE-20 — Improper input validation: input is not validated (or is validated incorrectly) before use, allowing malformed or malicious data to alter control/data flow.  
**Verdict:** `vulnerable_files`  
**Budget:** 7/8 terminal cmds, 14 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The DNS zone parsing logic in src/lib.rs implements DNS zone record parsing and validation. It parses DNS zone records and validates fields such as target_addr, expected_ip, and aliases. This is the likely location of CWE-20 (improper input validation) because DNS zone bundle formats can contain malformed or maliciously crafted DNS records (e.g., wildcard '*', resource record addresses with embedded control characters, or malformed record formats). The code parses these records and validates their fields, so missing or incorrect validation of record-level inputs can allow malformed DNS data to alter control/data flow.

## Commands run
```
$ ls
$ grep -R "input_validation\|validate\|sanitize\|from_str\|parse\|deserialize\|deserialize\|read\|read_line\|read_to_string\|from_slice\|from_utf8\|unwrap\|expect\|unsafe" --include='*.rs'
$ find src -maxdepth 2 | head -n 200
$ grep -R "request\|request\|http\|net\|req\|url\|uri\|parse\(" src --include='*.rs'
$ grep -R "request" src --include='*.rs'
$ grep -R "http" src --include='*.rs'
$ grep -R "net" src --include='*.rs'
$ grep -R "parse\(" src --include='*.rs'
$ cat src/lib.rs
$ grep -R "parse_dns_zone\|parse_dns_zone_record\|parse_dns_zone_bundle\|parse_dns_zone_records\|DnsZoneRecord\|from_str\(" src --include='*.rs'
$ grep -R "parse_dns_zone_record\|parse_dns_zone_records\|parse_dns_zone\|DnsZoneRecord\|from_str\(" src --include='*.rs'
```
