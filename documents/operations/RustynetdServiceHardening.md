# Rustynetd Systemd Hardening Profile

## Purpose
Define a production-safe service profile for `rustynetd` with least privilege, fail-closed behavior, and predictable restart semantics.

## Service File
- Source: `scripts/systemd/rustynetd.service`
- Install helper: `scripts/systemd/install_rustynetd_service.sh`

## Hardening Controls
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
- `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`
- `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`
- `ReadWritePaths=/run/rustynet /var/lib/rustynet /etc/rustynet`
- `UMask=0077`

## Reliability Controls
- `Restart=on-failure`
- `RestartSec=2s`
- `StartLimitBurst=5`
- `StartLimitIntervalSec=60`
- `RuntimeDirectory=rustynet` with mode `0700`
- `StateDirectory=rustynet` with mode `0700`

## Required Runtime Files
- `/etc/rustynet/wireguard.key` (`0600`)
- `/var/lib/rustynet/rustynetd.trust` (integrity-checked trust evidence)

## Verification
1. `sudo systemctl daemon-reload`
2. `sudo systemctl enable --now rustynetd.service`
3. `sudo systemctl --no-pager --full status rustynetd.service`
4. `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- status`
