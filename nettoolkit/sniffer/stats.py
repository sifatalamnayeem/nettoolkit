"""Summaries and simple display filters for decoded packets."""

from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Callable, Optional

from .packets import Packet


class Stats:
    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.protocols: Counter = Counter()
        self.talkers: Counter = Counter()
        self.dst_ports: Counter = Counter()
        self.dns_names: Counter = Counter()

    def add(self, pkt: Packet) -> None:
        self.packets += 1
        self.bytes += pkt.length
        self.protocols[pkt.protocol] += 1
        if pkt.src_ip:
            self.talkers[pkt.src_ip] += pkt.length
        if pkt.dst_port is not None and pkt.protocol in ("TCP", "UDP", "DNS"):
            self.dst_ports[pkt.dst_port] += 1
        if pkt.dns and not pkt.dns[2]:  # count queries, not responses
            self.dns_names[pkt.dns[0]] += 1


def format_summary(stats: Stats, top: int = 5) -> str:
    if stats.packets == 0:
        return "No packets captured."
    lines = [f"Packets: {stats.packets}    Bytes: {stats.bytes:,}", "", "Protocols:"]
    lines += [f"  {name:<10}{count}" for name, count in stats.protocols.most_common(top)]
    if stats.talkers:
        lines += ["", "Top sources (by bytes):"]
        lines += [f"  {ip:<42}{size:,}" for ip, size in stats.talkers.most_common(top)]
    if stats.dst_ports:
        lines += ["", "Most used destination ports:"]
        lines += [f"  {port:<10}{count}" for port, count in stats.dst_ports.most_common(top)]
    if stats.dns_names:
        lines += ["", "Most queried DNS names:"]
        lines += [f"  {name:<42}{count}" for name, count in stats.dns_names.most_common(top)]
    return "\n".join(lines)


def make_filter(
    proto: Optional[str] = None, host: Optional[str] = None, port: Optional[int] = None
) -> Callable[[Packet], bool]:
    """Build a display filter. `proto` is one of tcp, udp, icmp, arp, dns."""
    if proto is not None:
        proto = proto.lower()
        if proto not in ("tcp", "udp", "icmp", "arp", "dns"):
            raise ValueError("--proto must be one of: tcp, udp, icmp, arp, dns")
    if host is not None:
        host = str(ipaddress.ip_address(host))  # ValueError for bad input
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("--port must be between 1 and 65535")

    def match(pkt: Packet) -> bool:
        if proto == "dns" and pkt.dns is None:
            return False
        if proto == "icmp" and not pkt.protocol.startswith("ICMP"):
            return False
        if proto in ("tcp", "udp", "arp") and pkt.protocol.lower() != proto:
            if not (proto == "udp" and pkt.protocol == "DNS" and pkt.dns):
                return False
        if host is not None and host not in (pkt.src_ip, pkt.dst_ip):
            return False
        if port is not None and port not in (pkt.src_port, pkt.dst_port):
            return False
        return True

    return match
