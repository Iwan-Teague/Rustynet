#!/usr/bin/env python3
"""Minimal RFC 5389 STUN binding responder for the netns internet simulator.

This is LAB TOOLING, not a Rustynet component. It stands in for the public
STUN servers (stun.l.google.com, Cloudflare, ...) that real Rustynet peers
query — Rustynet itself ships only a STUN *client* and points it at public
servers via `traversal_stun_servers`. In the simulator the "internet" has no
public STUN server, so this responder runs on the svc namespace and reflects
each querying endpoint's *observed source* (its NAT-translated ip:port) back
as XOR-MAPPED-ADDRESS — exactly the srflx candidate a real STUN server returns.

Wire format mirrors crates/rustynetd/src/stun_client.rs so the real client
parses the reply unchanged: binding request 0x0001 -> binding response 0x0101
with a single XOR-MAPPED-ADDRESS (0x0020) attribute. IPv4 and IPv6 both
supported.

Usage:
    stun_responder.py [--bind ADDR] [--port N]   # default 0.0.0.0:3478, also ::
Run inside the svc namespace, e.g.:
    ip netns exec rnsim-svc python3 stun_responder.py --bind 100.64.0.254 --port 3478
"""
import argparse
import socket
import struct
import sys

STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
MAGIC_BE = struct.pack(">I", STUN_MAGIC_COOKIE)


def build_response(tx_id: bytes, src_ip: str, src_port: int, is_v6: bool) -> bytes:
    """Build a binding response carrying XOR-MAPPED-ADDRESS of (src_ip, src_port)."""
    xport = src_port ^ (STUN_MAGIC_COOKIE >> 16)
    if is_v6:
        family = 0x02
        raw = socket.inet_pton(socket.AF_INET6, src_ip)
        key = MAGIC_BE + tx_id  # 16-byte XOR key per RFC 5389 §15.2
        xaddr = bytes(a ^ b for a, b in zip(raw, key))
    else:
        family = 0x01
        raw = socket.inet_pton(socket.AF_INET, src_ip)
        xaddr = bytes(a ^ b for a, b in zip(raw, MAGIC_BE))
    # attribute value: reserved(1)=0, family(1), xport(2), xaddr(4|16)
    attr_val = struct.pack(">BBH", 0, family, xport) + xaddr
    attr = struct.pack(">HH", STUN_ATTR_XOR_MAPPED_ADDRESS, len(attr_val)) + attr_val
    header = struct.pack(">HH", STUN_BINDING_RESPONSE, len(attr)) + MAGIC_BE + tx_id
    return header + attr


def valid_request(buf: bytes) -> bytes | None:
    """Return the 12-byte transaction id if buf is a valid binding request, else None."""
    if len(buf) < 20:
        return None
    msg_type, _msg_len, cookie = struct.unpack(">HHI", buf[:8])
    if msg_type != STUN_BINDING_REQUEST or cookie != STUN_MAGIC_COOKIE:
        return None
    return buf[8:20]


def serve(bind: str, port: int) -> None:
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    print(f"stun-responder: listening on {bind}:{port}", flush=True)
    while True:
        buf, addr = sock.recvfrom(1024)
        tx_id = valid_request(buf)
        if tx_id is None:
            continue
        src_ip, src_port = addr[0], addr[1]
        is_v6 = ":" in src_ip
        sock.sendto(build_response(tx_id, src_ip, src_port, is_v6), addr)


def main() -> int:
    ap = argparse.ArgumentParser(description="minimal STUN binding responder (lab tooling)")
    ap.add_argument("--bind", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=3478, help="bind port (default 3478)")
    args = ap.parse_args()
    try:
        serve(args.bind, args.port)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
