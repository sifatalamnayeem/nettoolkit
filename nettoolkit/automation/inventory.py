"""Device inventory. Passwords are never stored here; see connection.credentials_from_env."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")  # also used as a folder/file name
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]{0,252}$")
FORBIDDEN_KEYS = {"password", "secret", "passwd", "enable_password", "token"}


@dataclass(frozen=True)
class Device:
    name: str
    host: str
    device_type: str          # a Netmiko device_type, e.g. cisco_ios, juniper_junos, mikrotik_routeros
    port: int = 22


def load_inventory(path: str | Path) -> List[Device]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read inventory '{path}': {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"inventory '{path}' is not valid JSON: {exc}") from exc

    items = raw.get("devices") if isinstance(raw, dict) else None
    if not items or not isinstance(items, list):
        raise ValueError("inventory must be an object with a non-empty 'devices' list")

    devices, seen = [], set()
    for i, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"device #{i}: must be an object")
        leaked = FORBIDDEN_KEYS & {k.lower() for k in item}
        if leaked:
            raise ValueError(
                f"device #{i}: do not store credentials in the inventory file "
                f"({', '.join(sorted(leaked))}); use NETTOOL_USER / NETTOOL_PASS instead"
            )
        name, host = str(item.get("name", "")), str(item.get("host", ""))
        dtype = str(item.get("device_type", ""))
        if not NAME_RE.match(name):
            raise ValueError(f"device #{i}: 'name' must be 1-64 letters, digits, '.', '_' or '-'")
        if not HOST_RE.match(host):
            raise ValueError(f"device '{name}': invalid 'host'")
        if not re.match(r"^[a-z0-9_]+$", dtype):
            raise ValueError(f"device '{name}': 'device_type' is required (e.g. cisco_ios)")
        try:
            port = int(item.get("port", 22))
        except (TypeError, ValueError):
            raise ValueError(f"device '{name}': 'port' must be a number")
        if not 1 <= port <= 65535:
            raise ValueError(f"device '{name}': 'port' must be 1-65535")
        if name in seen:
            raise ValueError(f"duplicate device name '{name}'")
        seen.add(name)
        devices.append(Device(name=name, host=host, device_type=dtype, port=port))
    return devices
