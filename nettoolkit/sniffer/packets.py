"""Decode raw Ethernet frames (standard library only).

Frames come straight off the wire, so every function here treats them as hostile:
nothing raises on short, truncated or random bytes, and any text taken from a packet
(DNS names) is reduced to printable ASCII before it can reach a terminal.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import asdict, dataclass
from typing import Optional, Tuple

ETH_IPV4, ETH_ARP, ETH_IPV6, ETH_VLAN = 0x0800, 0x0806, 0x86DD, 0x8100
PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMP6 = 1, 6, 17, 58

TCP_FLAGS = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")]
ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request", 11: "time-exceeded"}
ICMP6_TYPES = {1: "dest-unreachable", 3: "time-exceeded", 128: "echo-request", 129: "echo-reply",
               135: "neighbor-solicit", 136: "neighbor-advert"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}

# (name, query type, is_response)
DnsInfo = Tuple[str, str, bool]


@dataclass
class Packet:
    ts: float = 0.0
    length: int = 0
    src_mac: str = ""
    dst_mac: str = ""
    layer3: str = ""              # ARP, IPv4, IPv6 or the raw EtherType
    protocol: str = ""            # TCP, UDP, DNS, ICMP, ICMPv6, ARP, ...
    src_ip: str = ""
    dst_ip: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info: str = ""
    truncated: bool = False
    dns: Optional[DnsInfo] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        """One line, e.g. '   74B  TCP     10.0.0.5:51000 -> 93.184.216.34:443  [SYN] seq=1000'."""
        if not self.layer3:
            return f"{self.length:>5}B  truncated frame"
        if self.protocol == "ARP":
            return f"{self.length:>5}B  ARP     {self.info}"

        def end(ip: str, port: Optional[int]) -> str:
            if not ip:
                return "?"
            if port is None:
                return ip
            return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

        where = (f"{end(self.src_ip, self.src_port)} -> {end(self.dst_ip, self.dst_port)}"
                 if self.src_ip else f"{self.src_mac} -> {self.dst_mac}")
        flag = "  (truncated)" if self.truncated else ""
        return f"{self.length:>5}B  {self.protocol:<7} {where}  {self.info}{flag}".rstrip()


def mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def safe_text(raw: bytes, limit: int = 80) -> str:
    """Printable ASCII only; network data must never reach the terminal unfiltered."""
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in raw[:limit])
    return text + ("…" if len(raw) > limit else "")


def _tcp_flags(value: int) -> str:
    return ",".join(name for bit, name in TCP_FLAGS if value & bit) or "none"


def parse_dns(payload: bytes) -> Optional[DnsInfo]:
    """Read the question of a DNS message. Returns None when it is not a sane DNS message."""
    if len(payload) < 12:
        return None
    flags, qdcount = struct.unpack("!2xHH", payload[:6])
    if qdcount < 1:
        return None
    labels, pos = [], 12
    while True:
        if pos >= len(payload):
            return None
        size = payload[pos]
        if size == 0:
            pos += 1
            break
        # compression pointers do not occur in a question; anything odd means "not DNS"
        if size & 0xC0 or pos + 1 + size > len(payload) or len(labels) >= 30:
            return None
        labels.append(safe_text(payload[pos + 1: pos + 1 + size], 63))
        pos += 1 + size
    if pos + 4 > len(payload) or not labels:
        return None
    qtype = struct.unpack("!H", payload[pos: pos + 2])[0]
    return ".".join(labels), DNS_TYPES.get(qtype, f"TYPE{qtype}"), bool(flags & 0x8000)


def _transport(pkt: Packet, proto: int, data: bytes) -> None:
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
            dns = parse_dns(data[8:])
            if dns:
                name, qtype, is_response = dns
                pkt.protocol, pkt.dns = "DNS", dns
                pkt.info = f"DNS {'response' if is_response else 'query'} {qtype} {name}"
    elif proto in (PROTO_ICMP, PROTO_ICMP6):
        pkt.protocol = "ICMP" if proto == PROTO_ICMP else "ICMPv6"
        if not data:
            pkt.truncated = True
            return
        names = ICMP_TYPES if proto == PROTO_ICMP else ICMP6_TYPES
        pkt.info = names.get(data[0], f"type {data[0]}")
    else:
        pkt.protocol = f"proto-{proto}"


def parse_frame(frame: bytes, ts: float = 0.0) -> Optional[Packet]:
    """Decode one Ethernet frame. Returns None if it is too short to be a frame at all."""
    if len(frame) < 14:
        return None
    pkt = Packet(ts=ts, length=len(frame), dst_mac=mac(frame[0:6]), src_mac=mac(frame[6:12]))
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
        sender = str(ipaddress.IPv4Address(payload[14:18]))
        target = str(ipaddress.IPv4Address(payload[24:28]))
        pkt.src_ip, pkt.dst_ip = sender, target
        pkt.info = (f"who has {target}? tell {sender}" if op == 1
                    else f"{sender} is at {mac(payload[8:14])}" if op == 2 else f"op {op}")
    elif ethertype == ETH_IPV4:
        pkt.layer3 = "IPv4"
        if len(payload) < 20 or payload[0] >> 4 != 4:
            pkt.truncated = True
            return pkt
        ihl, proto = (payload[0] & 0x0F) * 4, payload[9]
        pkt.src_ip = str(ipaddress.IPv4Address(payload[12:16]))
        pkt.dst_ip = str(ipaddress.IPv4Address(payload[16:20]))
        if ihl < 20 or len(payload) < ihl:
            pkt.truncated = True
            return pkt
        if struct.unpack("!H", payload[6:8])[0] & 0x1FFF:      # later fragment: no transport header
            pkt.protocol, pkt.info = f"proto-{proto}", "fragment"
            return pkt
        _transport(pkt, proto, payload[ihl:])
    elif ethertype == ETH_IPV6:
        pkt.layer3 = "IPv6"
        if len(payload) < 40 or payload[0] >> 4 != 6:
            pkt.truncated = True
            return pkt
        pkt.src_ip = str(ipaddress.IPv6Address(payload[8:24]))
        pkt.dst_ip = str(ipaddress.IPv6Address(payload[24:40]))
        _transport(pkt, payload[6], payload[40:])               # extension headers are not walked
    else:
        pkt.layer3 = pkt.protocol = f"0x{ethertype:04x}"
    return pkt
