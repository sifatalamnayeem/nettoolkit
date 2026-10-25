"""Parse sshd lines from auth.log / secure / journald exports.

Understands both timestamp styles:
    Oct 25 02:14:01 web01 sshd[1021]: ...            (classic syslog, no year)
    2026-10-25T02:14:01.123456+06:00 web01 sshd[...] (RFC 3339, rsyslog/journald)
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, Optional

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

_CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_ISO = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+\S+\s+"
    r"sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")


@dataclass(frozen=True)
class LogEvent:
    ts: datetime      # naive; timezone-aware input is converted to UTC first
    kind: str         # "failed", "accepted" or "invalid_user"
    user: str
    ip: str
    method: str = ""


def clean_text(value: str, limit: int = 64) -> str:
    """Make attacker-controlled text safe to print (no control or escape characters)."""
    cleaned = re.sub(r"[^\x20-\x7e]", "?", value)
    return cleaned[:limit] + ("…" if len(cleaned) > limit else "")


def _valid_ip(text: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _classic_ts(match, year: Optional[int], now: datetime) -> Optional[datetime]:
    month = MONTHS.get(match["mon"])
    if month is None:
        return None
    hour, minute, second = (int(x) for x in match["time"].split(":"))
    day = int(match["day"])
    try:
        if year is not None:
            return datetime(year, month, day, hour, minute, second)
        ts = datetime(now.year, month, day, hour, minute, second)
        if ts > now + timedelta(days=1):  # log from last year (e.g. December read in January)
            ts = ts.replace(year=now.year - 1)
        return ts
    except ValueError:  # impossible date such as Feb 30
        return None


def _iso_ts(text: str) -> Optional[datetime]:
    try:
        ts = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts


def parse_line(line: str, year: Optional[int] = None, now: Optional[datetime] = None) -> Optional[LogEvent]:
    now = now or datetime.now()
    line = line.rstrip("\n")

    m = _CLASSIC.match(line)
    if m:
        ts = _classic_ts(m, year, now)
    else:
        m = _ISO.match(line)
        ts = _iso_ts(m["iso"]) if m else None
    if not m or ts is None:
        return None

    msg = m["msg"]
    for pattern, kind in ((_FAILED, "failed"), (_ACCEPTED, "accepted"), (_INVALID, "invalid_user")):
        hit = pattern.match(msg)
        if hit:
            ip = _valid_ip(hit["ip"])
            if ip is None:
                return None
            method = hit.groupdict().get("method") or ""
            return LogEvent(ts=ts, kind=kind, user=hit["user"], ip=ip, method=method)
    return None


def parse_lines(
    lines: Iterable[str], year: Optional[int] = None, now: Optional[datetime] = None
) -> Iterator[LogEvent]:
    now = now or datetime.now()
    for line in lines:
        event = parse_line(line, year=year, now=now)
        if event is not None:
            yield event
