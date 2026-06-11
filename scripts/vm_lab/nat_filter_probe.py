#!/usr/bin/env python3
"""UDP NAT filtering probe for the netns internet simulator.

LAB TOOLING - not a Rustynet component. The ``init`` side runs behind a NAT,
optionally learns its server-reflexive endpoint from the in-sim STUN responder,
then listens on the same UDP socket for a filtering-test packet. The ``probe``
side sends one or more UDP packets from a chosen source IP:port.
"""
import argparse
import os
import socket
import struct
import sys
import time

STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
STUN_ATTR_MAPPED_ADDRESS = 0x0001


def parse_endpoint(value: str) -> tuple[str, int]:
    host, port = value.rsplit(":", 1)
    return host, int(port)


def parse_mapped_address(buf: bytes) -> tuple[str, int]:
    i = 20
    while i + 4 <= len(buf):
        attr_type, attr_len = struct.unpack(">HH", buf[i:i + 4])
        val = buf[i + 4:i + 4 + attr_len]
        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS and len(val) >= 8:
            port = struct.unpack(">H", val[2:4])[0] ^ (STUN_MAGIC_COOKIE >> 16)
            ip = socket.inet_ntoa(
                bytes(
                    a ^ b
                    for a, b in zip(
                        val[4:8],
                        struct.pack(">I", STUN_MAGIC_COOKIE),
                    )
                )
            )
            return ip, port
        if attr_type == STUN_ATTR_MAPPED_ADDRESS and len(val) >= 8:
            port = struct.unpack(">H", val[2:4])[0]
            ip = socket.inet_ntoa(val[4:8])
            return ip, port
        i += 4 + attr_len + ((4 - attr_len % 4) % 4)
    raise ValueError("no mapped-address attribute in STUN response")


def stun_query(
    sock: socket.socket,
    server: tuple[str, int],
    timeout: float,
) -> tuple[tuple[str, int], tuple[str, int]]:
    tx_id = os.urandom(12)
    req = struct.pack(">HHI", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE) + tx_id
    sock.settimeout(timeout)
    sock.sendto(req, server)
    while True:
        buf, addr = sock.recvfrom(1024)
        if len(buf) < 20:
            continue
        msg_type, _msg_len, cookie = struct.unpack(">HHI", buf[:8])
        if msg_type == 0x0101 and cookie == STUN_MAGIC_COOKIE and buf[8:20] == tx_id:
            return parse_mapped_address(buf), (addr[0], addr[1])


def write_text(path: str, text: str) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)


def init(args: argparse.Namespace) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind_host, args.bind_port))
    mapped = sock.getsockname()
    received = False
    received_from = ""
    detail = "none"

    if args.stun:
        try:
            mapped, stun_from = stun_query(sock, parse_endpoint(args.stun), args.timeout)
        except (OSError, ValueError, socket.timeout) as exc:
            print(f"stun_failed={exc}", file=sys.stderr)
            sock.close()
            return 1
        if args.mapped_file:
            write_text(args.mapped_file, f"{mapped[0]}:{mapped[1]}\n")
        if args.count_stun_response:
            received = True
            received_from = f"{stun_from[0]}:{stun_from[1]}"
            detail = "stun_response"
    elif args.mapped_file:
        write_text(args.mapped_file, f"{mapped[0]}:{mapped[1]}\n")

    deadline = time.monotonic() + args.listen_secs
    while time.monotonic() < deadline:
        remaining = max(0.0, min(args.timeout, deadline - time.monotonic()))
        if remaining == 0.0:
            break
        sock.settimeout(remaining)
        try:
            _buf, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        received = True
        received_from = f"{addr[0]}:{addr[1]}"
        detail = "udp_probe"
        break
    sock.close()

    print(
        "mapped={}:{} received={} from={} detail={}".format(
            mapped[0],
            mapped[1],
            "yes" if received else "no",
            received_from or "-",
            detail,
        ),
        flush=True,
    )
    return 0


def probe(args: argparse.Namespace) -> int:
    target = parse_endpoint(args.target)
    bind = parse_endpoint(args.bind)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(bind)
    payload = args.payload.encode("utf-8")
    for _ in range(args.count):
        sock.sendto(payload, target)
        time.sleep(args.delay)
    sock.close()
    print(
        f"sent={args.count} bind={bind[0]}:{bind[1]} target={target[0]}:{target[1]}",
        flush=True,
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="NAT filtering UDP probe")
    sub = ap.add_subparsers(dest="cmd", required=True)

    init_ap = sub.add_parser("init", help="bind behind NAT, optionally STUN, then listen")
    init_ap.add_argument("--bind-host", default="0.0.0.0")
    init_ap.add_argument("--bind-port", type=int, default=51820)
    init_ap.add_argument("--stun", metavar="HOST:PORT")
    init_ap.add_argument("--mapped-file")
    init_ap.add_argument("--listen-secs", type=float, default=3.0)
    init_ap.add_argument("--timeout", type=float, default=1.0)
    init_ap.add_argument("--count-stun-response", action="store_true")
    init_ap.set_defaults(func=init)

    probe_ap = sub.add_parser("probe", help="send UDP packets from a chosen source")
    probe_ap.add_argument("--target", required=True, metavar="HOST:PORT")
    probe_ap.add_argument("--bind", required=True, metavar="HOST:PORT")
    probe_ap.add_argument("--count", type=int, default=3)
    probe_ap.add_argument("--delay", type=float, default=0.05)
    probe_ap.add_argument("--payload", default="rustynet-nat-filter-probe")
    probe_ap.set_defaults(func=probe)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
