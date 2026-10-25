"""Small internet speed test using only the standard library.

It talks to a server that exposes Cloudflare's speed test endpoints:
    GET  {server}/__down?bytes=N   -> returns N bytes
    POST {server}/__up             -> accepts a body
Latency is the median TCP connect time to the server.
"""

from __future__ import annotations

import socket
import statistics
import time
import urllib.request
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urlparse

DEFAULT_SERVER = "https://speed.cloudflare.com"
USER_AGENT = "nettoolkit-speedlog/0.2"


@dataclass
class SpeedResult:
    ping_ms: Optional[float]
    download_mbps: Optional[float]
    upload_mbps: Optional[float]
    server: str

    def to_dict(self) -> dict:
        return asdict(self)


def _host_port(server: str) -> tuple[str, int]:
    parsed = urlparse(server)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("server must be a full http:// or https:// URL")
    return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def measure_ping(server: str, count: int = 5, timeout: float = 3.0) -> Optional[float]:
    host, port = _host_port(server)
    samples = []
    for _ in range(count):
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except OSError:
            continue
        samples.append((time.perf_counter() - start) * 1000)
    return round(statistics.median(samples), 1) if samples else None


def measure_download(server: str, size_bytes: int, timeout: float = 30.0) -> float:
    req = urllib.request.Request(
        f"{server.rstrip('/')}/__down?bytes={size_bytes}",
        headers={"User-Agent": USER_AGENT},
    )
    total = 0
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
    elapsed = max(time.perf_counter() - start, 1e-6)
    return total * 8 / elapsed / 1_000_000


def measure_upload(server: str, size_bytes: int, timeout: float = 30.0) -> float:
    req = urllib.request.Request(
        f"{server.rstrip('/')}/__up",
        data=bytes(size_bytes),
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/octet-stream"},
        method="POST",
    )
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()
    elapsed = max(time.perf_counter() - start, 1e-6)
    return size_bytes * 8 / elapsed / 1_000_000


def run_speedtest(
    server: str = DEFAULT_SERVER,
    download_mb: float = 10,
    upload_mb: float = 2,
    do_upload: bool = True,
    timeout: float = 30.0,
) -> SpeedResult:
    """Run ping + download (+ upload). A failed step is reported as None."""
    _host_port(server)  # validate early
    ping = measure_ping(server)

    download = upload = None
    try:
        download = round(measure_download(server, int(download_mb * 1_000_000), timeout), 2)
    except (OSError, ValueError):
        pass
    if do_upload:
        try:
            upload = round(measure_upload(server, int(upload_mb * 1_000_000), timeout), 2)
        except (OSError, ValueError):
            pass

    if ping is None and download is None and upload is None:
        raise RuntimeError(f"could not reach speed test server {server}")
    return SpeedResult(ping, download, upload, server)
