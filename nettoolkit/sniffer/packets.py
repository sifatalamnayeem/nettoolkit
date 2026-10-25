"""Decode raw Ethernet frames (standard library only).

Every function works on bytes and never raises on malformed input: truncated or
garbage frames simply produce a Packet with fewer fields filled in. That matters
because a sniffer sees whatever is on the wire, including hostile traffic.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import asdict, dataclass
from typing import Optional

ETH_IPV4, ETH_ARP, ETH_IPV6, ETH_VLAN = 0x0800, 0x0806, 0x86DD, 0x8100
PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMP6 = 1, 6, 17, 58

TCP_FLAGS = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")]
ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request", 11: "time-exceeded"}
ICMP6_TYPES = {1: "dest-unreachable", 3: "time-exceeded", 128: "echo-request", 129: "echo-reply",
               135: "neighbor-solicit", 136: "neighbor-advert"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 12: "PTR", 6: "SOA", 255: "ANY"}


@dataclass
class Packet:
    length: int
    src_mac: str = ""
    dst_mac: str = ""
    layer3: str = ""          # ARP, IPv4, IPv6 or the raw EtherType
    protocol: str = ""        # TCP, UDP, ICMP, ICMPv6, ARP...
    src: str = ""
    dst: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info: str = ""
    truncated: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def safe_text(raw: bytes, limit: int = 80) -> str:
    """Printable ASCII only; network data must never reach the terminal unfiltered."""
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in raw[:limit])
    return text + ("…" if len(raw) > limit else "")


def _tcp_flags(value: int) -> str:
    names = [name for bit, name in TCP_FLAGS if value & bit]
    return ",".join(names) or "none"


def parse_dns_query(payload: bytes) -> str:
    """Return e.g. 'query A example.com' / 'response A example.com'; '' when not parseable."""
    if len(payload) < 12:
        return ""
    flags, qdcount = struct.unpack("!2xHH", payload[:6])
    if qdcount < 1:
        return ""
    labels, pos = [], 12
    while pos < len(payload):
        size = payload[pos]
        if size == 0:
            pos += 1
            break
        if size & 0xC0 or size > 63 or pos + 1 + size > len(payload) or len(labels) > 30:
            return ""  # compression pointers do not appear in the question; anything odd is rejected
        labels.append(safe_text(payload[pos + 1: pos + 1 + size], 63))
        pos += 1 + size
    else:
        return ""
    if pos + 4 > len(payload) or not labels:
        return ""
    qtype = struct.unpack("!H", payload[pos: pos + 2])[0]
    kind = "response" if flags & 0x8000 else "query"
    return f"DNS {kind} {DNS_TYPES.get(qtype, qtype)} {'.'.join(labels)}"


def _parse_transport(pkt: Packet, proto: int, data: bytes) -> None:
    if proto == PROTO_TCP:
        pkt.protocol = "TCP"
        if len(data) < 20:
            pkt.truncated = True
            return
        sport, dport, seq, _ack, offset_flags = struct.unpack("!HHIIH", data[:14])
        pkt.src_port, pkt.dst_port = sport, dport
        pkt.info = f"[{_tcp_flags(offset_flags & 0x3F)}] seq={seq}"
    elif proto == PROTO_UDP:
        pkt.protocol = "UDP"
        if len(data) < 8:
            pkt.truncated = True
            return
        sport, dport, ulen = struct.unpack("!HHH", data[:6])
        pkt.src_port, pkt.dst_port = sport, dport
        pkt.info = f"len={ulen}"
        if 53 in (sport, dport):
            dns = parse_dns_query(data[8:])
            if dns:
                pkt.protocol, pkt.info = "DNS", dns
    elif proto in (PROTO_ICMP, PROTO_ICMP6):
        pkt.protocol = "ICMP" if proto == PROTO_ICMP else "ICMPv6"
        if not data:
            pkt.truncated = True
            return
        names = ICMP_TYPES if proto == PROTO_ICMP else ICMP6_TYPES
        pkt.info = names.get(data[0], f"type {data[0]}")
    else:
        pkt.protocol = f"proto-{proto}"


def parse_frame(frame: bytes) -> Packet:
    pkt = Packet(length=len(frame))
    if len(frame) < 14:
        pkt.truncated = True
        return pkt
    pkt.dst_mac, pkt.src_mac = mac(frame[0:6]), mac(frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]
    payload = frame[14:]
    if ethertype == ETH_VLAN and len(payload) >= 4:
        ethertype = struct.unpack("!H", payload[2:4])[0]
        payload = payload[4:]

    if ethertype == ETH_ARP:
        pkt.layer3 = pkt.protocol = "ARP"
        if len(payload) < 28:
            pkt.truncated = True
            return pkt
        op = struct.unpack("!H", payload[6:8])[0]
        sender, target = str(ipaddress.IPv4Address(payload[14:18])), str(ipaddress.IPv4Address(payload[24:28]))
        pkt.src, pkt.dst = sender, target
        pkt.info = (f"who has {target}? tell {sender}" if op == 1
                    else f"{sender} is at {mac(payload[8:14])}" if op == 2 else f"op {op}")
    elif ethertype == ETH_IPV4:
        pkt.layer3 = "IPv4"
        if len(payload) < 20 or payload[0] >> 4 != 4:
            pkt.truncated = True
            return pkt
        ihl = (payload[0] & 0x0F) * 4
        proto = payload[9]
        pkt.src, pkt.dst = str(ipaddress.IPv4Address(payload[12:16])), str(ipaddress.IPv4Address(payload[16:20]))
        if ihl < 20 or len(payload) < ihl:
            pkt.truncated = True
            return pkt
        frag_offset = struct.unpack("!H", payload[6:8])[0] & 0x1FFF
        if frag_offset:  # later fragment: no transport header to read
            pkt.protocol, pkt.info = f"proto-{proto}", "fragment"
            return pkt
        _parse_transport(pkt, proto, payload[ihl:])
    elif ethertype == ETH_IPV6:
        pkt.layer3 = "IPv6"
        if len(payload) < 40 or payload[0] >> 4 != 6:
            pkt.truncated = True
            return pkt
        pkt.src, pkt.dst = str(ipaddress.IPv6Address(payload[8:24])), str(ipaddress.IPv6Address(payload[24:40]))
        _parse_transport(pkt, payload[6], payload[40:])  # extension headers are not walked
    else:
        pkt.layer3 = pkt.protocol = f"0x{ethertype:04x}"
    return pkt


def summarize(pkt: Packet) -> str:
    def endpoint(addr: str, port: Optional[int]) -> str:
        if not addr:
            return "?"
        return f"[{addr}]:{port}" if port is not None and ":" in addr else (
            f"{addr}:{port}" if port is not None else addr)

    if not pkt.layer3:
        return f"{pkt.length:>5}B  truncated frame"
    if pkt.protocol == "ARP":
        return f"{pkt.length:>5}B  ARP     {pkt.info}"
    where = f"{endpoint(pkt.src, pkt.src_port)} -> {endpoint(pkt.dst, pkt.dst_port)}" if pkt.src else (
        f"{pkt.src_mac} -> {pkt.dst_mac}")
    flag = "  (truncated)" if pkt.truncated else ""
    return f"{pkt.length:>5}B  {pkt.protocol:<7} {where}  {pkt.info}{flag}".rstrip()
