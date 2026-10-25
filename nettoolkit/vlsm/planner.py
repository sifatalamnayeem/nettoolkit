"""VLSM (variable length subnet masking) planner for IPv4.

Give it a block such as 192.168.10.0/24 and the departments with the number of hosts
each needs. It allocates the biggest department first, which keeps every subnet
aligned and wastes no space between them.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import List, Sequence, Tuple

MAX_HOSTS = 2 ** 24


@dataclass
class Allocation:
    name: str
    requested: int
    network: str
    prefix: int
    netmask: str
    first_host: str
    last_host: str
    broadcast: str
    usable: int

    @property
    def spare(self) -> int:
        return self.usable - self.requested

    def to_dict(self) -> dict:
        return {**asdict(self), "spare": self.spare}


@dataclass
class Plan:
    base: str
    allocations: List[Allocation] = field(default_factory=list)
    free_blocks: List[str] = field(default_factory=list)
    total_addresses: int = 0
    used_addresses: int = 0

    @property
    def utilisation(self) -> float:
        return round(100 * self.used_addresses / self.total_addresses, 1) if self.total_addresses else 0.0

    def to_dict(self) -> dict:
        return {"base": self.base, "utilisation_pct": self.utilisation,
                "allocations": [a.to_dict() for a in self.allocations], "free_blocks": self.free_blocks}


def parse_requirement(text: str) -> Tuple[str, int]:
    """'Sales:50' -> ('Sales', 50)."""
    name, sep, count = text.rpartition(":")
    name = name.strip()
    if not sep or not name:
        raise ValueError(f"'{text}': use the form Name:hosts, e.g. Sales:50")
    try:
        hosts = int(count)
    except ValueError:
        raise ValueError(f"'{text}': host count must be a whole number")
    if not 1 <= hosts <= MAX_HOSTS:
        raise ValueError(f"'{text}': host count must be between 1 and {MAX_HOSTS}")
    return " ".join(name.split()), hosts


def block_size(hosts: int) -> int:
    """Smallest power-of-two block with room for the hosts plus network and broadcast (min /30)."""
    size = 4
    while size - 2 < hosts:
        size *= 2
    return size


def plan_vlsm(base_cidr: str, requirements: Sequence[Tuple[str, int]]) -> Plan:
    net = ipaddress.ip_network(base_cidr.strip(), strict=False)
    if net.version != 4:
        raise ValueError("the VLSM planner supports IPv4 only")
    if not requirements:
        raise ValueError("give at least one requirement, e.g. -r Sales:50")
    names = [n.lower() for n, _ in requirements]
    if len(set(names)) != len(names):
        raise ValueError("each name must be unique")

    ordered = sorted(requirements, key=lambda r: -r[1])      # stable: ties keep the given order
    start, end = int(net.network_address), int(net.network_address) + net.num_addresses
    cursor = start
    plan = Plan(base=str(net), total_addresses=net.num_addresses)
    needed = sum(block_size(h) for _, h in requirements)
    if needed > net.num_addresses:
        raise ValueError(
            f"{net} has {net.num_addresses} addresses but these subnets need {needed} "
            f"(each includes network and broadcast addresses). Use a bigger block."
        )

    for name, hosts in ordered:
        size = block_size(hosts)
        prefix = 32 - (size.bit_length() - 1)
        if cursor + size > end:   # cannot happen after the check above, kept as a safety net
            raise ValueError(f"ran out of space while placing '{name}'")
        sub = ipaddress.ip_network((cursor, prefix))
        plan.allocations.append(Allocation(
            name=name, requested=hosts, network=str(sub.network_address), prefix=prefix,
            netmask=str(sub.netmask), first_host=str(sub.network_address + 1),
            last_host=str(sub.broadcast_address - 1), broadcast=str(sub.broadcast_address),
            usable=size - 2,
        ))
        plan.used_addresses += size
        cursor += size

    if cursor < end:
        plan.free_blocks = [str(n) for n in ipaddress.summarize_address_range(
            ipaddress.IPv4Address(cursor), ipaddress.IPv4Address(end - 1))]
    return plan


def format_plan(plan: Plan) -> str:
    rows = [f"{'NAME':<18}{'NEED':<7}{'SUBNET':<20}{'MASK':<17}{'HOST RANGE':<34}{'USABLE':<8}SPARE"]
    for a in plan.allocations:
        rows.append(
            f"{a.name:<18}{a.requested:<7}{a.network + '/' + str(a.prefix):<20}{a.netmask:<17}"
            f"{a.first_host + ' - ' + a.last_host:<34}{a.usable:<8}{a.spare}"
        )
    rows.append("")
    rows.append(f"{plan.base}: {plan.used_addresses} of {plan.total_addresses} addresses used ({plan.utilisation}%)")
    rows.append("Free space: " + (", ".join(plan.free_blocks) if plan.free_blocks else "none"))
    return "\n".join(rows)
