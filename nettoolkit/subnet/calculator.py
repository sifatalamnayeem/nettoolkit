"""Subnet calculator built on the standard library `ipaddress` module."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, asdict
from typing import List


@dataclass
class SubnetInfo:
    input: str
    version: int
    network: str
    netmask: str
    wildcard: str
    prefix_length: int
    broadcast: str | None
    first_host: str | None
    last_host: str | None
    total_addresses: int
    usable_hosts: int
    is_private: bool

    def to_dict(self) -> dict:
        return asdict(self)


def calculate(cidr: str) -> SubnetInfo:
    """Return details for an IP/CIDR string such as '192.168.1.10/24'.

    Host bits are allowed (strict=False), so '192.168.1.10/24' works.
    Raises ValueError for invalid input.
    """
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    total = net.num_addresses

    if net.version == 4:
        broadcast = str(net.broadcast_address)
        if net.prefixlen == 32:
            usable, first, last = 1, str(net.network_address), str(net.network_address)
        elif net.prefixlen == 31:
            # RFC 3021 point-to-point link: both addresses usable
            usable = 2
            first, last = str(net.network_address), str(net.broadcast_address)
        else:
            usable = total - 2
            hosts = net.hosts()
            first = str(next(hosts))
            last = str(net.broadcast_address - 1)
        wildcard = str(net.hostmask)
    else:
        # IPv6 has no broadcast address
        broadcast = None
        usable = total
        first = str(net.network_address)
        last = str(net.broadcast_address)
        wildcard = str(net.hostmask)

    return SubnetInfo(
        input=cidr.strip(),
        version=net.version,
        network=str(net.network_address),
        netmask=str(net.netmask),
        wildcard=wildcard,
        prefix_length=net.prefixlen,
        broadcast=broadcast,
        first_host=first,
        last_host=last,
        total_addresses=total,
        usable_hosts=usable,
        is_private=net.is_private,
    )


def split_subnet(cidr: str, new_prefix: int) -> List[str]:
    """Split a network into smaller subnets with the given prefix length."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    if new_prefix <= net.prefixlen:
        raise ValueError(
            f"new prefix /{new_prefix} must be longer than /{net.prefixlen}"
        )
    max_prefix = net.max_prefixlen
    if new_prefix > max_prefix:
        raise ValueError(f"new prefix must be <= /{max_prefix}")
    return [str(s) for s in net.subnets(new_prefix=new_prefix)]
