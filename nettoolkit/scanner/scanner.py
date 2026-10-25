"""LAN host discovery and TCP port scanner (standard library only).

Only scan networks and hosts that you own or have permission to test.
"""

from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    8080: "http-alt",
}


@dataclass
class PortResult:
    port: int
    open: bool
    service: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HostResult:
    ip: str
    alive: bool
    hostname: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def parse_ports(spec: str) -> List[int]:
    """Parse '22,80,443' or '1-1024' or a mix like '22,80,8000-8100'."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"ports out of range (1-65535): {sorted(bad)[:5]}")
    return sorted(ports)


def _service_name(port: int) -> str:
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _check_port(host: str, port: int, timeout: float) -> PortResult:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            is_open = True
    except (OSError, socket.timeout):
        is_open = False
    return PortResult(port=port, open=is_open, service=_service_name(port))


def scan_ports(
    host: str,
    ports: Optional[Iterable[int]] = None,
    timeout: float = 0.5,
    workers: int = 100,
    only_open: bool = True,
) -> List[PortResult]:
    """TCP connect scan. Returns results sorted by port number."""
    port_list = list(ports) if ports is not None else sorted(COMMON_PORTS)
    results: List[PortResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check_port, host, p, timeout) for p in port_list]
        for fut in as_completed(futures):
            res = fut.result()
            if res.open or not only_open:
                results.append(res)
    return sorted(results, key=lambda r: r.port)


def _ping(ip: str, timeout: float) -> bool:
    """Send one ICMP echo using the system `ping` command."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), ip]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _resolve(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def discover_hosts(
    cidr: str,
    timeout: float = 1.0,
    workers: int = 64,
    resolve_names: bool = True,
    max_hosts: int = 1024,
) -> List[HostResult]:
    """Ping sweep a network and return the hosts that answered."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    if net.version != 4:
        raise ValueError("host discovery currently supports IPv4 only")
    if net.num_addresses > max_hosts + 2:
        raise ValueError(
            f"{cidr} has too many hosts for a sweep (limit {max_hosts}); "
            "use a smaller network such as a /24"
        )
    targets = [str(h) for h in net.hosts()] or [str(net.network_address)]

    alive: List[HostResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_ping, ip, timeout): ip for ip in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            if fut.result():
                name = _resolve(ip) if resolve_names else None
                alive.append(HostResult(ip=ip, alive=True, hostname=name))
    return sorted(alive, key=lambda h: ipaddress.ip_address(h.ip))
