"""Deterministic PCAP fixture generator for Cyber-Clops QA.

Builds tests/fixtures/generated.pcap with known flows:
- 1x TCP 10.0.0.1:1234 to 10.0.0.2:80
- 1x UDP DNS query for lab.example.com to 8.8.8.8:53

Usage: python3 tools/pcap_gen.py
Checks with: cargo test pcap
No third party deps, stdlib only.
"""
import struct
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "generated.pcap"


def eth() -> bytes:
    dst = bytes(6)
    src = bytes(6)
    return dst + src + struct.pack("!H", 0x0800)


def ipv4(proto: int, src: bytes, dst: bytes, payload: bytes) -> bytes:
    total = 20 + len(payload)
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, src, dst)
    return head + payload


def tcp(sport: int, dport: int) -> bytes:
    return struct.pack("!HHIIHHHH", sport, dport, 0, 0, 0x5000, 0, 0, 0)


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def dns_query(name: str) -> bytes:
    head = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(struct.pack("B", len(p)) + p.encode() for p in name.split("."))
    return head + qname + b"\x00" + struct.pack("!HH", 1, 1)


def frame(ip_payload: bytes) -> bytes:
    return eth() + ip_payload


def main() -> None:
    frames = [
        frame(ipv4(6, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]), tcp(1234, 80))),
        frame(
            ipv4(
                17,
                bytes([10, 0, 0, 1]),
                bytes([8, 8, 8, 8]),
                udp(5353, 53, dns_query("lab.example.com")),
            )
        ),
    ]
    with open(OUT, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for pkt in frames:
            f.write(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)))
            f.write(pkt)
    print(f"wrote {OUT} with {len(frames)} packets")


if __name__ == "__main__":
    sys.exit(main())
