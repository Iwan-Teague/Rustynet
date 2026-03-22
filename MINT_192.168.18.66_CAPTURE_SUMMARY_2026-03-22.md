# Mint 192.168.18.66 RustyNet Capture Summary (2026-03-22)

## Host
- Underlay host: `192.168.18.66`
- SSH user: `mint`
- RustyNet node id: `mint-66`
- RustyNet role: `admin`
- RustyNet interface: `rustynet0`
- WireGuard listen port: `51820`

## Pinned SSH Identity
- Host key type: `ssh-ed25519`
- Host key:
  - `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOP2DZUxIrJxbRbqwhYDFyZIYO5ZGSksLTkEDj2Zjlvg`
- Fingerprint:
  - `SHA256:8ImytqZ2mePHxWoSpfiSgUPKtMYB5DyKp8aaJqY2UEw`

## RustyNet Identity
- WireGuard public key (base64):
  - `BlB9nKKT7lAO6XlGhmtuSN+T9kSvFOU9MMXUxLwyKUI=`
- WireGuard public key (hex):
  - `06507d9ca293ee500ee97946866b6e48df93f644af14e53d30c5d4c4bc322942`

## Verifier Keys (base64)
- Assignment verifier key:
  - `oTfbIoFuoqp0b+90XKFHgZGpwGECqVwhrOiuzwuXnkM=`
- Traversal verifier key:
  - `DqRw5UGZlU0b1/Qpvl9ix6s/WpqAxuy040cIXcLs0xQ=`
- DNS zone verifier key:
  - `7c4MZX5Kqs/ypRdSLK2iVbex1YjbD43Ra0pClMOGi78=`
- Trust verifier key:
  - `QWKO4oiPPjeSZgMqXrRq70Evk5Lj7CUSXJ65kwRrxtc=`

## Evidence Bundle (Local Mac)
- Tarball:
  - `/tmp/rn-mint66-crossnet-20260322T134742Z.tgz`
- Checksum file:
  - `/tmp/rn-mint66-crossnet-20260322T134742Z.tgz.sha256`
- Extracted directory:
  - `/tmp/rn-mint66-crossnet-20260322T134742Z.extract/rn-mint66-crossnet-20260322T134742Z`
- Discovery bundle:
  - `/tmp/rn-mint66-crossnet-20260322T134742Z.extract/rn-mint66-crossnet-20260322T134742Z/network_discovery_bundle.json`
- Discovery validation (strict):
  - `/tmp/rn-mint66-crossnet-20260322T134742Z.extract/rn-mint66-crossnet-20260322T134742Z/network_discovery_validation.md`

## Runtime Status
- `rustynetd.service`: `active`
- `rustynetd-privileged-helper.service`: `active`
- `rustynetd-managed-dns.service`: `active`
- Signed-state verify: assignment/dns/trust passed.
- Traversal verify is intentionally skipped because active traversal bundle is absent on a single-node bootstrap.

## Important Security Note
- `rustynet status` reports `state=FailClosed` with traversal-authority bootstrap error.
- This is expected under strict fail-closed posture until real cross-network signed assignment + traversal state includes actual managed peers.
- No insecure fallback/downgrade was enabled.

## Ready Inputs For Cross-Network Setup
1. This Mint discovery bundle and verifier keys.
2. A discovery bundle from at least one node on the other network.
3. Signed assignment state that includes both sides.
4. Signed traversal state for required source/target pairs.
5. Post-apply handshake check (`wg show rustynet0 latest-handshakes`) on both sides.
