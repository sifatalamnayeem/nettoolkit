"""Back up device configs, keep history and show what changed since last time."""

from __future__ import annotations

import difflib
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from .connection import short_error
from .inventory import Device

DEFAULT_COMMAND = "show running-config"

# Lines that change on every run and would make every backup look "changed".
VOLATILE = re.compile(
    r"^\s*(!\s*(last configuration change|nvram config last updated|time:)|"
    r"building configuration|current configuration\s*:|ntp clock-period|"
    r"#\s*(by routeros|\w{3}/\d{2}/\d{4}))",
    re.IGNORECASE,
)


@dataclass
class BackupResult:
    device: str
    status: str                 # "new", "changed", "unchanged" or "failed"
    path: Optional[str] = None
    added: int = 0
    removed: int = 0
    diff: str = ""
    error: str = ""


def normalize(config: str) -> List[str]:
    return [ln.rstrip() for ln in config.splitlines() if ln.strip() and not VOLATILE.match(ln)]


def latest_backup(folder: Path) -> Optional[Path]:
    files = sorted(folder.glob("*.cfg")) if folder.is_dir() else []
    return files[-1] if files else None


def _write_private(path: Path, text: str) -> None:
    """Configs contain secrets (hashes, SNMP strings), so files are owner-only (0600)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")


def _backup_one(device: Device, connect: Callable, out_dir: Path, command: str) -> BackupResult:
    try:
        conn = connect(device)
        try:
            config = conn.send_command(command)
        finally:
            conn.disconnect()
    except Exception as exc:  # one broken device must not stop the whole run
        return BackupResult(device.name, "failed", error=short_error(exc))

    if not config or not config.strip():
        return BackupResult(device.name, "failed", error="device returned an empty config")

    folder = out_dir / device.name
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    previous = latest_backup(folder)
    new_lines = normalize(config)

    diff_text, added, removed, status = "", 0, 0, "new"
    if previous is not None:
        old_lines = normalize(previous.read_text(encoding="utf-8", errors="replace"))
        if old_lines == new_lines:
            return BackupResult(device.name, "unchanged", path=str(previous))
        diff = list(difflib.unified_diff(old_lines, new_lines, previous.name, "now", lineterm="", n=2))
        added = sum(1 for d in diff if d.startswith("+") and not d.startswith("+++"))
        removed = sum(1 for d in diff if d.startswith("-") and not d.startswith("---"))
        diff_text, status = "\n".join(diff), "changed"

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = folder / f"{device.name}_{stamp}.cfg"
    _write_private(path, config)
    return BackupResult(device.name, status, path=str(path), added=added, removed=removed, diff=diff_text)


def backup_devices(
    devices: Sequence[Device],
    connect: Callable,
    out_dir: str | Path,
    command: str = DEFAULT_COMMAND,
    workers: int = 5,
) -> List[BackupResult]:
    """Back up every device (in parallel). Results keep the inventory order."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(devices)))) as pool:
        return list(pool.map(lambda d: _backup_one(d, connect, out, command), devices))
