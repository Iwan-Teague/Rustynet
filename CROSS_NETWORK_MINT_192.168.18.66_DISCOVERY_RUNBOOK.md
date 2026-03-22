# Cross-Network Discovery Runbook (Mint `192.168.18.66`)

Use this to collect exactly what is needed for secure cross-network RustyNet validation.

## Scope
- Target host: `mint@192.168.18.66`
- Goal: collect signed-state, discovery, and host identity evidence
- Security model: fail-closed; no plaintext secret exports

## 1) Run On Mint (`mint@192.168.18.66`)
Open terminal on Mint and run:

```bash
set -euo pipefail

cd ~/Rustynet
sudo -v

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="/tmp/rn-cross-network-mint66-${TS}"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

NODE_ID="$(cat /var/lib/rustynet/node-id 2>/dev/null || true)"
if [ -z "$NODE_ID" ]; then
  NODE_ID="$(cat /etc/rustynet/node-id 2>/dev/null || hostname)"
fi

echo "$NODE_ID" > "$OUT_DIR/node_id.txt"

# Host identity and network baseline
hostnamectl > "$OUT_DIR/hostnamectl.txt"
ip -4 -o addr show up scope global > "$OUT_DIR/ip4_addr_global.txt"
ip -4 route show > "$OUT_DIR/ip4_routes.txt"
getent hosts "$(hostname)" > "$OUT_DIR/getent_hosts_hostname.txt" || true

# SSH host identity for strict pinning verification
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub > "$OUT_DIR/ssh_host_ed25519_fingerprint.txt"
sudo cat /etc/ssh/ssh_host_ed25519_key.pub > "$OUT_DIR/ssh_host_ed25519_key.pub"

# Daemon/socket/service state
sudo test -S /run/rustynet/rustynetd.sock
sudo systemctl is-active rustynetd.service > "$OUT_DIR/rustynetd_active.txt"
sudo systemctl is-active rustynetd-privileged-helper.service > "$OUT_DIR/rustynetd_helper_active.txt"
sudo wg show rustynet0 > "$OUT_DIR/wg_show_rustynet0.txt" || true
sudo wg show rustynet0 endpoints > "$OUT_DIR/wg_endpoints_rustynet0.txt" || true

# Signed-state verification (same checks as cross-network preflight)
sudo env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet assignment verify \
  --bundle /var/lib/rustynet/rustynetd.assignment \
  --verifier-key /etc/rustynet/assignment.pub \
  --watermark /var/lib/rustynet/rustynetd.assignment.watermark \
  --expected-node-id "$NODE_ID" \
  --max-age-secs 900 \
  --max-clock-skew-secs 2 \
  > "$OUT_DIR/verify_assignment.txt"

sudo env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet traversal verify \
  --bundle /var/lib/rustynet/rustynetd.traversal \
  --verifier-key /etc/rustynet/traversal.pub \
  --watermark /var/lib/rustynet/rustynetd.traversal.watermark \
  --expected-source-node-id "$NODE_ID" \
  --max-age-secs 900 \
  --max-clock-skew-secs 2 \
  > "$OUT_DIR/verify_traversal.txt"

sudo env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet trust verify \
  --evidence /var/lib/rustynet/rustynetd.trust \
  --verifier-key /etc/rustynet/trust-evidence.pub \
  --watermark /var/lib/rustynet/rustynetd.trust.watermark \
  --max-age-secs 900 \
  --max-clock-skew-secs 2 \
  > "$OUT_DIR/verify_trust.txt"

sudo env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet dns zone verify \
  --bundle /var/lib/rustynet/rustynetd.dns-zone \
  --verifier-key /etc/rustynet/dns-zone.pub \
  --expected-zone-name rustynet \
  --expected-subject-node-id "$NODE_ID" \
  > "$OUT_DIR/verify_dns_zone.txt"

# Discovery bundle generation
bash scripts/operations/collect_network_discovery_info.sh \
  --quiet \
  --output "$OUT_DIR/discovery-mint66.json"

# Discovery bundle schema + security validation
cargo run --quiet -p rustynet-cli -- ops validate-network-discovery-bundle \
  --bundle "$OUT_DIR/discovery-mint66.json" \
  --max-age-seconds 900 \
  --require-verifier-keys \
  --require-daemon-active \
  --require-socket-present \
  --output "$OUT_DIR/discovery-mint66-validation.md"

# Hashes + package
sha256sum "$OUT_DIR/discovery-mint66.json" > "$OUT_DIR/discovery-mint66.sha256"
sha256sum "$OUT_DIR"/* > "$OUT_DIR/all_files.sha256"

tar -C /tmp -czf "/tmp/rn-cross-network-mint66-${TS}.tgz" "$(basename "$OUT_DIR")"
sha256sum "/tmp/rn-cross-network-mint66-${TS}.tgz" > "/tmp/rn-cross-network-mint66-${TS}.tgz.sha256"

echo "Evidence bundle: /tmp/rn-cross-network-mint66-${TS}.tgz"
echo "Bundle hash:    /tmp/rn-cross-network-mint66-${TS}.tgz.sha256"
```

## 2) Send Back To Me
Send these outputs:

- `/tmp/rn-cross-network-mint66-<TS>.tgz`
- `/tmp/rn-cross-network-mint66-<TS>.tgz.sha256`
- The content of `ssh_host_ed25519_fingerprint.txt`

## 3) Optional: Pull Artifacts From Your Main Machine
From your main machine:

```bash
scp mint@192.168.18.66:/tmp/rn-cross-network-mint66-*.tgz /tmp/
scp mint@192.168.18.66:/tmp/rn-cross-network-mint66-*.tgz.sha256 /tmp/
sha256sum -c /tmp/rn-cross-network-mint66-*.tgz.sha256
```

## 4) Notes
- Do **not** share private keys or passphrases.
- Discovery output includes public keys, endpoint candidates, and signed-artifact metadata only.
- Keep this Mint node on the current network untouched until I confirm capture is complete.
