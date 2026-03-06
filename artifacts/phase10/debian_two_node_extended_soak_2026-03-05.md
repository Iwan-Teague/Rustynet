# Debian Two-Node Extended Soak Validation

- generated_at_utc: 2026-03-05T18:44:20Z
- commit: 18e42ff
- exit_host: debian@192.168.18.40
- client_host: debian@192.168.18.37
- soak_window_utc: 2026-03-05T18:39:40Z -> 2026-03-05T18:44:11Z
- samples_per_host: 10
- sample_interval: 30s

## Soak Checks

| Check | Result | Evidence |
|---|---|---|
| Exit daemon active throughout | PASS | `daemon=active` on all 10 exit samples |
| Exit assignment timer active throughout | PASS | `timer=active` on all 10 exit samples |
| Exit state remains active/non-restricted | PASS | `state=ExitActive restricted=false serving=true` on all 10 exit samples |
| Exit assignment freshness rotates during soak | PASS | `last_assignment: 1772735898 -> 1772736039 -> 1772736174` |
| Exit handshake freshness advances | PASS | `hs: 1772735865 -> 1772736121 -> 1772736250` |
| Client daemon active throughout | PASS | `daemon=active` on all 10 client samples |
| Client assignment timer active throughout | PASS | `timer=active` on all 10 client samples |
| Client state remains active/non-restricted | PASS | `state=ExitActive restricted=false exit_node=exit-node` on all 10 client samples |
| Client assignment freshness rotates during soak | PASS | `last_assignment: 1772735917 -> 1772736057 -> 1772736195` |
| Client default route stays on tunnel | PASS | `route=1.1.1.1 dev rustynet0 ...` on all 10 client samples |

## Conclusion

Extended post-install soak remained healthy for the full window with no service degradation, no fail-open behavior, and continued signed assignment refresh rotation on both nodes.
