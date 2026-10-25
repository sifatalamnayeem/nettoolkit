"""Connections to devices. Netmiko is optional and imported only when needed."""

from __future__ import annotations

import getpass
import os
import sys
from dataclasses import dataclass, field
from typing import Optional

from .inventory import Device


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str = field(repr=False)          # repr=False: never printed in logs or tracebacks
    secret: Optional[str] = field(default=None, repr=False)


def credentials_from_env() -> Credentials:
    """NETTOOL_USER and NETTOOL_PASS (optional NETTOOL_SECRET for 'enable'). Prompts if on a terminal."""
    user = os.environ.get("NETTOOL_USER", "").strip()
    password = os.environ.get("NETTOOL_PASS", "")
    if not user:
        raise ValueError("set NETTOOL_USER (and NETTOOL_PASS) to log in to the devices")
    if not password:
        if not sys.stdin.isatty():
            raise ValueError("set NETTOOL_PASS, or run from a terminal to be prompted")
        password = getpass.getpass(f"Password for {user}: ")
    return Credentials(user, password, os.environ.get("NETTOOL_SECRET") or None)


def netmiko_connect(device: Device, creds: Credentials, timeout: float = 30.0):
    """Return an open Netmiko connection (caller must call .disconnect())."""
    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise RuntimeError("Netmiko is not installed. Run: pip install 'nettoolkit[automation]'")
    params = {
        "device_type": device.device_type,
        "host": device.host,
        "port": device.port,
        "username": creds.username,
        "password": creds.password,
        "conn_timeout": timeout,
        "banner_timeout": timeout,
    }
    if creds.secret:
        params["secret"] = creds.secret
    conn = ConnectHandler(**params)
    if creds.secret:
        conn.enable()
    return conn


def short_error(exc: BaseException) -> str:
    """One safe line for reports (no traceback, bounded length)."""
    text = " ".join(str(exc).split()) or type(exc).__name__
    return f"{type(exc).__name__}: {text}"[:200]
