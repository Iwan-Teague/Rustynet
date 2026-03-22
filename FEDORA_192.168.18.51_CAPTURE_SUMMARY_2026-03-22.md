# Fedora 192.168.18.51 RustyNet Capture Summary (2026-03-22)

## Host
- Underlay host: `192.168.18.51`
- SSH user: `fedora`
- RustyNet node id: `fedora-51`
- RustyNet role: `admin`
- RustyNet interface: `rustynet0`
- WireGuard listen port: `51820`

## Pinned SSH Identity
- Host key type: `ssh-ed25519`
- Host key:
  - `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOBDH6fs7l73hb3FBoHxtDf8cai17DjEm3wCy1P3eJAW`
- Fingerprint:
  - `SHA256:3oa252ZOmNrQh51fx9BOTUyMz4RsgqnOWNJ95fX8gMA`

## RustyNet Identity
- WireGuard public key (base64):
  - `iNxZR6RpNHLzfIMbLlW3A7emf8QrdaZXu+G+mydBKl8=`
- WireGuard public key (hex):
  - `88dc5947a4693472f37c831b2e55b703b7a67fc42b75a657bbe1be9b27412a5f`

## Verifier Keys (base64)
- Assignment verifier key:
  - `fEYQxtaaGWsEH19khYdv3Tk5bUNjbjvDO4JZS/hDtUk=`
- Traversal verifier key:
  - `g4vxbAbv7DKtFHKX1y9LEe9VVOt2rZkuYg7TUILTjD0=`
- DNS zone verifier key:
  - `rckRm6vBhDtx2YFyuirQjVGSzoA14hdJTsb0HpNxBr0=`
- Trust verifier key:
  - `eGR1z6bHEmqo51kYP08whIKQrpg0VzFfQDUVLP06tBo=`

## Evidence Bundle (Local Mac)
- Tarball:
  - `/tmp/rn-fedora51-crossnet-20260322T133154Z.tgz`
- Checksum file:
  - `/tmp/rn-fedora51-crossnet-20260322T133154Z.tgz.sha256`
- Extracted directory:
  - `/tmp/rn-fedora51-crossnet-20260322T133154Z.extract/rn-fedora51-crossnet-20260322T133154Z`
- Discovery bundle:
  - `/tmp/rn-fedora51-crossnet-20260322T133154Z.extract/rn-fedora51-crossnet-20260322T133154Z/network_discovery_bundle.json`
- Discovery validation (strict):
  - `/tmp/rn-fedora51-crossnet-20260322T133154Z.extract/rn-fedora51-crossnet-20260322T133154Z/network_discovery_validation.md`

## Runtime Status
- `rustynetd.service`: `active`
- `rustynetd-privileged-helper.service`: `active`
- `rustynetd-managed-dns.service`: `active`
- Signed-state verify: assignment/dns/trust passed.
- Traversal verify is intentionally skipped because active traversal bundle is absent on a single-node bootstrap.

## Important Security Note
- `rustynet status` currently reports `state=FailClosed` with traversal-authority bootstrap error.
- This is expected under strict fail-closed posture until real cross-network signed assignment + traversal state includes actual managed peers.
- No insecure fallback/downgrade was enabled.

## What I Need From the Other Network To Establish Cross-Network Connectivity
1. A discovery bundle from at least one node on the other network.
2. Signed assignment state that includes `fedora-51` and the remote peer(s).
3. Signed traversal state for the relevant source/target pairs.
4. Distribution/apply of those signed bundles to both sides.
5. A post-apply handshake check (`wg show rustynet0 latest-handshakes`) on both sides.
