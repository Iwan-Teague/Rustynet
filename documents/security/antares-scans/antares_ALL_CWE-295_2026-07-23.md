# Antares scan — `ALL` — CWE-295

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-295 — Improper certificate/signature validation: a certificate or signature is not validated, or validation can be bypassed.  
**Verdict:** `vulnerable_files`  
**Budget:** 16/30 terminal cmds, 17 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynet-dns-zone/src/lib.rs` | inspected |

## Model reasoning

The DNS zone bundle verification logic in crates/rustynet-dns-zone/src/lib.rs implements signature validation (verify_signed_dns_zone_bundle) using Ed25519 VerifyingKeys derived from keys passed in SignedDnsZoneBundle. The code decodes hex keys and verifies signatures with these keys, but there is no validation that the key source is trusted/validated against a trusted key store. This can allow an attacker to sign DNS zone bundles with arbitrary keys, bypassing signature verification and enabling DNS zone manipulation (manipulating DNS records, tampering with DNS zones). The vulnerable pattern is improper certificate/signature validation of the DNS zone signing key.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "cert" /workspace/repo/crates | head -n 200
$ grep -RIn "X509" /workspace/repo/crates | head -n 200
$ grep -RIn "verify" /workspace/repo/crates | head -n 200
$ grep -RIn "Certificate" /workspace/repo/crates | head -n 200
$ grep -RIn "openssl" /workspace/repo/crates | head -n 200
$ grep -RIn "X509_unparsed" /workspace/repo/crates | head -n 200
$ grep -RIn "X509_unparsed" /workspace/repo | head -n 200
$ grep -RIn "verify_signed_dns_zone_bundle" /workspace/repo/crates | head -n 200
$ cat crates/rustynet-dns-zone/src/lib.rs
$ sed -n '850,900p' crates/rustynet-dns-zone/src/lib.rs
$ grep -RIn "verify_signed_dns_zone_bundle" crates | head -n 200
$ cat crates/rustynet-dns-zone/src/lib.rs | head -n 950
$ wc -l crates/rustynet-dns-zone/src/lib.rs
$ sed -n '220,400p' crates/rustynet-dns-zone/src/lib.rs
```
