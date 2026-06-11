#!/usr/bin/env python3
"""NAT mapping-behaviour classifier for the netns internet simulator (RFC 5780-style).

LAB TOOLING — not a Rustynet component. Run from inside an endpoint namespace,
behind that site's NAT router. It binds ONE UDP socket and sends a STUN binding
request from it to TWO different STUN server addresses, then compares the
server-reflexive (mapped) endpoints reported back:

  - If the mapped port is the SAME toward both servers, the NAT uses
    endpoint-INDEPENDENT mapping (full-cone / restricted-cone / port-restricted
    cone). Hole punching can work: the peer learns one stable public port.
  - If the mapped port DIFFERS per destination, the NAT uses
    endpoint-DEPENDENT mapping (symmetric). Hole punching to a STUN-learned
    port fails; this is the hard case that forces relay.

This is exactly the property the §4.1 NAT-profile matrix must verify: that
apply_nat_profile's port_restricted_cone/full_cone are endpoint-independent and
symmetric is endpoint-dependent. The STUN wire format matches
crates/rustynetd/src/stun_client.rs so the same servers serve the real client.

Usage:
    nat_probe.py --stun HOST:PORT --stun HOST:PORT [--timeout SECS]
Exit code 0 on success (both servers answered); prints machine-parseable lines:
    mapped[0]=IP:PORT
    mapped[1]=IP:PORT
    mapping=endpoint-independent | endpoint-dependent
"""
import argparse
import os
import socket
import struct
import sys

STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
STUN_ATTR_MAPPED_ADDRESS = 0x0001


def query(sock: socket.socket, server: tuple[str, int], timeout: float):
    """Send a binding request from sock to server, return (ip, port) mapped endpoint."""
    tx_id = os.urandom(12)
    req = struct.pack(">HHI", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE) + tx_id
    sock.settimeout(timeout)
    sock.sendto(req, server)
    buf, _ = sock.recvfrom(1024)
    i = 20
    while i + 4 <= len(buf):
        attr_type, attr_len = struct.unpack(">HH", buf[i:i + 4])
        val = buf[i + 4:i + 4 + attr_len]
        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS and len(val) >= 8:
            port = struct.unpack(">H", val[2:4])[0] ^ (STUN_MAGIC_COOKIE >> 16)
            ip = socket.inet_ntoa(bytes(a ^ b for a, b in zip(val[4:8], struct.pack(">I", STUN_MAGIC_COOKIE))))
            return ip, port
        if attr_type == STUN_ATTR_MAPPED_ADDRESS and len(val) >= 8:
            port = struct.unpack(">H", val[2:4])[0]
            ip = socket.inet_ntoa(val[4:8])
            return ip, port
        i += 4 + attr_len + ((4 - attr_len % 4) % 4)
    raise ValueError("no mapped-address attribute in response")


def main() -> int:
    ap = argparse.ArgumentParser(description="NAT mapping-behaviour classifier (lab tooling)")
    ap.add_argument("--stun", action="append", required=True, metavar="HOST:PORT",
                    help="STUN server (give at least two distinct servers)")
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()
    servers = []
    for s in args.stun:
        host, port = s.rsplit(":", 1)
        servers.append((host, int(port)))
    if len(servers) < 2:
        print("need at least two --stun servers", file=sys.stderr)
        return 2

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    mapped = []
    try:
        for srv in servers:
            ip, port = query(sock, srv, args.timeout)
            mapped.append((ip, port))
    except (socket.timeout, OSError, ValueError) as e:
        print(f"probe failed: {e}", file=sys.stderr)
        return 1
    finally:
        sock.close()

    for idx, (ip, port) in enumerate(mapped):
        print(f"mapped[{idx}]={ip}:{port}")
    ports = {p for _, p in mapped}
    behaviour = "endpoint-independent" if len(ports) == 1 else "endpoint-dependent"
    print(f"mapping={behaviour}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
