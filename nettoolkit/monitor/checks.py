"""Individual health checks: HTTP, raw TCP port and SSL certificate expiry."""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

VALID_TYPES = ("http", "tcp", "ssl")
USER_AGENT = "nettoolkit-monitor/0.2"


@dataclass
class Target:
    name: str
    type: str
    params: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Target":
        data = dict(data)
        kind = str(data.pop("type", "")).lower()
        if kind not in VALID_TYPES:
            raise ValueError(f"target type must be one of {VALID_TYPES}, got '{kind}'")

        if kind == "http":
            url = str(data.get("url", ""))
            if not url.lower().startswith(("http://", "https://")):
                raise ValueError("http target needs a 'url' starting with http:// or https://")
            default_name = url
        elif kind == "tcp":
            if not data.get("host") or data.get("port") is None:
                raise ValueError("tcp target needs 'host' and 'port'")
            data["port"] = int(data["port"])
            default_name = f"{data['host']}:{data['port']}"
        else:  # ssl
            if not data.get("host"):
                raise ValueError("ssl target needs 'host'")
            data["port"] = int(data.get("port", 443))
            default_name = f"{data['host']} (ssl)"

        name = str(data.pop("name", "") or default_name)
        return cls(name=name, type=kind, params=data)


@dataclass
class CheckResult:
    target: str
    kind: str
    up: bool
    latency_ms: Optional[float]
    detail: str


def _short(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:200]


def check_http(target: Target) -> CheckResult:
    url = target.params["url"]
    timeout = float(target.params.get("timeout", 5))
    expect = target.params.get("expect_status")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
    except urllib.error.HTTPError as exc:  # server answered with 4xx/5xx
        status = exc.code
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return CheckResult(target.name, "http", False, None, _short(exc))
    latency = round((time.perf_counter() - start) * 1000, 1)

    ok = (status == int(expect)) if expect is not None else (200 <= status < 400)
    return CheckResult(target.name, "http", ok, latency, f"HTTP {status}")


def check_tcp(target: Target) -> CheckResult:
    host, port = target.params["host"], target.params["port"]
    timeout = float(target.params.get("timeout", 3))
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError as exc:
        return CheckResult(target.name, "tcp", False, None, _short(exc))
    latency = round((time.perf_counter() - start) * 1000, 1)
    return CheckResult(target.name, "tcp", True, latency, f"port {port} open")


def check_ssl(target: Target) -> CheckResult:
    """Fails when the certificate is invalid or expires within `warn_days`."""
    host, port = target.params["host"], target.params["port"]
    timeout = float(target.params.get("timeout", 5))
    warn_days = int(target.params.get("warn_days", 14))
    context = ssl.create_default_context()

    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except (ssl.SSLError, OSError) as exc:
        return CheckResult(target.name, "ssl", False, None, _short(exc))
    latency = round((time.perf_counter() - start) * 1000, 1)

    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    days_left = (expires - datetime.now(timezone.utc)).days
    ok = days_left >= warn_days
    detail = f"certificate expires in {days_left} days ({expires:%Y-%m-%d})"
    return CheckResult(target.name, "ssl", ok, latency, detail)


_CHECKS = {"http": check_http, "tcp": check_tcp, "ssl": check_ssl}


def run_check(target: Target) -> CheckResult:
    return _CHECKS[target.type](target)
