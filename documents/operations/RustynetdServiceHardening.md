# Rustynetd Systemd Hardening Profile

Status correction (verified 2026-03-05):
- Legacy requirement text that expects a persistent plaintext passphrase file is stale for current Linux hardened runtime.
- Runtime passphrase custody is credential-only via encrypted systemd credential blob (`LoadCredentialEncrypted=wg_key_passphrase:/etc/rustynet/credentials/wg_key_passphrase.cred`).
- Security risk truth: documenting plaintext passphrase files as required can lead to weaker key handling than current code policy.
- When decrypting signing credentials outside unit-injected `%d/...` paths, use explicit credential-name pinning for portability:
  `systemd-creds decrypt --name=signing_key_passphrase /etc/rustynet/credentials/signing_key_passphrase.cred <output>`.

## Purpose
Define a production-safe service profile for `rustynetd` with least privilege, fail-closed behavior, and predictable restart semantics.

## Service Files
- Source: `scripts/systemd/rustynetd.service`
- Install helper: `scripts/systemd/install_rustynetd_service.sh` (compatibility wrapper to `rustynet ops install-systemd`)
- Privileged helper unit: `scripts/systemd/rustynetd-privileged-helper.service`
- Trust refresh unit: `scripts/systemd/rustynetd-trust-refresh.service`
- Trust refresh timer: `scripts/systemd/rustynetd-trust-refresh.timer`
- Trust refresh service executes Rust directly: `ExecStart=/usr/local/bin/rustynet ops refresh-trust`
- Assignment refresh unit: `scripts/systemd/rustynetd-assignment-refresh.service`
- Assignment refresh timer: `scripts/systemd/rustynetd-assignment-refresh.timer`
- Assignment refresh service executes Rust directly: `ExecStart=/usr/local/bin/rustynet ops refresh-assignment`

Implementation note (runtime shell removal):
- Trust/assignment refresh runtime paths are now direct Rust service execution (`ExecStart=/usr/local/bin/rustynet ops ...`) with binary-custody preflight (`ops verify-runtime-binary-custody`).
- The install helper remains a compatibility wrapper to `rustynet ops install-systemd`.

## Hardening Controls (Daemon)
- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `PrivateTmp=true`
- `PrivateDevices=true`
- `ProtectControlGroups=true`
- `ProtectKernelTunables=true`
- `ProtectKernelModules=true`
- `ProtectKernelLogs=true`
- `MemoryDenyWriteExecute=true`
- `LockPersonality=true`
- `RestrictSUIDSGID=true`
- `RestrictRealtime=true`
- `SystemCallArchitectures=native`
- `CapabilityBoundingSet=` (empty)
- `AmbientCapabilities=` (empty)
- `ReadWritePaths=/run/rustynet /var/lib/rustynet /etc/rustynet`
- `UMask=0077`
- `EnvironmentFile=-/etc/default/rustynetd` with validated daemon/runtime values

## Hardening Controls (Privileged Helper)
- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `PrivateTmp=true`
- `PrivateDevices=true`
- `ProtectKernelTunables=false` (required for controlled sysctl writes)
- `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN CAP_DAC_OVERRIDE CAP_SYS_ADMIN`
- `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN CAP_DAC_OVERRIDE CAP_SYS_ADMIN`
- `ReadWritePaths=/run/rustynet /proc/sys/net/ipv4 /proc/sys/net/ipv6`

## Hardening Controls (Trust Refresh)
- Timer-driven one-shot refresh runs via `rustynetd-trust-refresh.service`.
- Uses `ProtectSystem=full`, `NoNewPrivileges=true`, and only `CAP_DAC_OVERRIDE` + `CAP_CHOWN` to access strict daemon-owned runtime paths and preserve trust evidence owner/group permissions.
- Reads encrypted signer key from `RUSTYNET_TRUST_SIGNER_KEY` and uses explicit passphrase input (`RUSTYNET_TRUST_SIGNING_KEY_PASSPHRASE_FILE`) loaded via `LoadCredentialEncrypted`.
- Enforces signer key ownership/mode guardrails (root-owned, owner-only) plus passphrase file ownership/mode checks.
- Encrypted signing artifacts under `/etc/rustynet` require parent directory mode `0750` (`root:<daemon-group>`) and file mode `0600`.
- Uses daemon-group-readable trust evidence (`root:<daemon-group>`, mode `0640`) when daemon group exists.
- Startup/migration cleanup paths for trust/signing artifacts use scrub+remove semantics (best-effort overwrite before unlink).

## Hardening Controls (Assignment Refresh)
- Timer-driven one-shot refresh runs via `rustynetd-assignment-refresh.service`.
- Auto-refresh remains fail-closed: stale/invalid signed assignment bundles are still rejected at daemon reconcile.
- Requires explicit enable (`RUSTYNET_ASSIGNMENT_AUTO_REFRESH=true`) and root-owned refresh config (`/etc/rustynet/assignment-refresh.env`).
- Reads encrypted signing secret from `RUSTYNET_ASSIGNMENT_SIGNING_SECRET` with explicit passphrase input (`RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE`) loaded via `LoadCredentialEncrypted`.
- Enforces root ownership/strict mode checks on both encrypted signing secret and passphrase source.
- Encrypted signing artifacts under `/etc/rustynet` require parent directory mode `0750` (`root:<daemon-group>`) and file mode `0600`.
- Reissues signed bundle with bounded TTL and rewrites artifacts atomically:
  - `/var/lib/rustynet/rustynetd.assignment` (`0640 root:<daemon-group>`)
  - `/etc/rustynet/assignment.pub` (`0644 root:root`)
- Legacy encrypted-key migration cleanup uses scrub+remove semantics (best-effort overwrite before unlink).

## Reliability Controls
- `Restart=on-failure`
- `RestartSec=2s`
- `StartLimitBurst=5`
- `StartLimitIntervalSec=60`
- `RuntimeDirectory=rustynet` with mode `0700`
- `StateDirectory=rustynet` with mode `0700`
- Trust refresh timer cadence:
  - `OnBootSec=45s`
  - `OnUnitActiveSec=60s`
  - `RandomizedDelaySec=10s`
  - `Persistent=true`
- Assignment refresh timer cadence:
  - `OnBootSec=45s`
  - `OnUnitActiveSec=60s`
  - `RandomizedDelaySec=10s`
  - `Persistent=true`

## Required Runtime Files
- `/etc/rustynet` directory (`0750`, `root:<daemon-group>`) for verifier + encrypted signing artifacts
- `/etc/rustynet/credentials` directory (`0700`, `root:root`) for encrypted credential blobs
- `/var/lib/rustynet/keys/wireguard.key.enc` (`0600`, encrypted at rest)
- `/etc/rustynet/credentials/wg_key_passphrase.cred` (`0600`, encrypted credential blob for passphrase custody)
- `/etc/rustynet/credentials/signing_key_passphrase.cred` (`0600`, encrypted credential blob for signing-key passphrase custody)
- `/run/rustynet/wireguard.key` (`0600`, runtime-decrypted key material)
- `/var/lib/rustynet/keys/wireguard.pub` (`0644`)
- `/var/lib/rustynet/rustynetd.trust` (`0640`, integrity-checked trust evidence)
- `/etc/rustynet/trust-evidence.pub` (pinned trust verifier key)
- `/etc/rustynet/trust-evidence.key` (`0600`, encrypted signer key; required only when trust auto-refresh is enabled)
- `/var/lib/rustynet/rustynetd.assignment` (`0640`, signed auto-tunnel bundle)
- `/etc/rustynet/assignment.pub` (`0644`, assignment verifier key)
- `/etc/rustynet/assignment.signing.secret` (`0600`, encrypted assignment signer secret; required only when assignment auto-refresh is enabled)
- `/etc/rustynet/assignment-refresh.env` (`0600`, root-owned assignment refresh input map)
- `/var/lib/rustynet/keys/wireguard.passphrase` should be absent in hardened Linux runtime (persistent plaintext passphrase files are rejected by preflight).

## Verification
1. `sudo systemctl daemon-reload`
2. `sudo ./scripts/systemd/install_rustynetd_service.sh`
3. `sudo systemctl --no-pager --full status rustynetd.service`
4. `sudo systemctl --no-pager --full status rustynetd-privileged-helper.service`
5. If `RUSTYNET_TRUST_AUTO_REFRESH=true`: `sudo systemctl --no-pager --full status rustynetd-trust-refresh.timer`
6. Trigger one refresh cycle: `sudo systemctl start rustynetd-trust-refresh.service`
7. If `RUSTYNET_ASSIGNMENT_AUTO_REFRESH=true`: `sudo systemctl --no-pager --full status rustynetd-assignment-refresh.timer`
8. Trigger one assignment refresh cycle: `sudo systemctl start rustynetd-assignment-refresh.service`
9. `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- status`
