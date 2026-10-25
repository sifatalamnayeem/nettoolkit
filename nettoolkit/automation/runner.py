"""Run commands on many devices. Read-only by default; changes need --apply."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, List, Sequence

from .connection import short_error
from .inventory import Device

READ_ONLY_PREFIXES = ("show ", "display ", "ping ", "traceroute ", "get ")


@dataclass
class CommandResult:
    device: str
    ok: bool
    output: str = ""
    error: str = ""
    sent: bool = True      # False for a dry run


def check_read_only(commands: Sequence[str]) -> None:
    bad = [c for c in commands if not c.lower().startswith(READ_ONLY_PREFIXES)]
    if bad:
        raise ValueError(
            f"'{bad[0]}' is not a read-only command (allowed: show, display, ping, traceroute, get). "
            "Use --config-file to send configuration changes."
        )


def _run_one(device: Device, connect: Callable, commands: Sequence[str], config_mode: bool, apply: bool) -> CommandResult:
    if config_mode and not apply:
        return CommandResult(device.name, True, "\n".join(f"(dry run) {c}" for c in commands), sent=False)
    try:
        conn = connect(device)
        try:
            if config_mode:
                output = conn.send_config_set(list(commands))
            else:
                output = "\n".join(f"$ {c}\n{conn.send_command(c)}" for c in commands)
        finally:
            conn.disconnect()
    except Exception as exc:
        return CommandResult(device.name, False, error=short_error(exc))
    return CommandResult(device.name, True, output)


def run_commands(
    devices: Sequence[Device],
    connect: Callable,
    commands: Sequence[str],
    config_mode: bool = False,
    apply: bool = False,
    workers: int = 5,
) -> List[CommandResult]:
    """Show commands run immediately. Configuration commands are only *sent* when apply=True;
    otherwise the result lists what would have been sent."""
    commands = [c.strip() for c in commands if c.strip() and not c.strip().startswith("#")]
    if not commands:
        raise ValueError("no commands to run")
    if not config_mode:
        check_read_only(commands)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(devices)))) as pool:
        return list(pool.map(lambda d: _run_one(d, connect, commands, config_mode, apply), devices))
