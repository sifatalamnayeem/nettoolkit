"""Turn parsed sshd events into findings: brute force, probing and risky logins."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Tuple

from .parser import LogEvent, clean_text


DUPLICATE_GAP = timedelta(seconds=5)


def _fmt(ts: datetime) -> str:
    return ts.isoformat(sep=" ", timespec="seconds")


@dataclass
class BruteForce:
    ip: str
    failures: int
    max_in_window: int
    distinct_users: int
    first_seen: str
    last_seen: str


@dataclass
class SuspiciousLogin:
    ip: str
    user: str
    method: str
    time: str
    prior_failures: int


@dataclass
class Report:
    threshold: int
    window_minutes: int
    events: int = 0
    failed_attempts: int = 0
    accepted_logins: int = 0
    unique_attacker_ips: int = 0
    top_ips: List[Tuple[str, int]] = field(default_factory=list)
    top_users: List[Tuple[str, int]] = field(default_factory=list)
    brute_force: List[BruteForce] = field(default_factory=list)
    suspicious_logins: List[SuspiciousLogin] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _max_in_window(times: List[datetime], window: timedelta) -> int:
    """Largest number of timestamps that fall inside any `window`-long span."""
    times = sorted(times)
    best, left = 0, 0
    for right, t in enumerate(times):
        while t - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def analyze(
    events: Iterable[LogEvent], threshold: int = 5, window_minutes: int = 10, top: int = 10
) -> Report:
    """Detect brute-force sources and logins that follow many failures.

    A failed attempt is a `Failed ...` line. `Invalid user` lines are counted too,
    unless the same attempt was already logged as a `Failed` line (sshd often
    writes both for one attempt).
    """
    events = sorted(events, key=lambda e: e.ts)
    window = timedelta(minutes=window_minutes)

    failed_times: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
    for e in events:
        if e.kind == "failed":
            failed_times[(e.ip, e.user)].append(e.ts)

    def already_logged_as_failed(e: LogEvent) -> bool:
        # sshd writes "Invalid user X" and "Failed password for invalid user X" a
        # moment apart for the same attempt, so treat close pairs as one attempt.
        return any(abs(t - e.ts) <= DUPLICATE_GAP for t in failed_times.get((e.ip, e.user), ()))

    attempts: List[LogEvent] = [
        e for e in events
        if e.kind == "failed" or (e.kind == "invalid_user" and not already_logged_as_failed(e))
    ]
    accepted = [e for e in events if e.kind == "accepted"]

    by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    for e in attempts:
        by_ip[e.ip].append(e)

    report = Report(threshold=threshold, window_minutes=window_minutes)
    report.events = len(events)
    report.failed_attempts = len(attempts)
    report.accepted_logins = len(accepted)
    report.unique_attacker_ips = len(by_ip)
    report.top_ips = Counter({ip: len(v) for ip, v in by_ip.items()}).most_common(top)
    report.top_users = Counter(clean_text(e.user) for e in attempts).most_common(top)

    for ip, items in by_ip.items():
        peak = _max_in_window([e.ts for e in items], window)
        if peak >= threshold:
            report.brute_force.append(BruteForce(
                ip=ip,
                failures=len(items),
                max_in_window=peak,
                distinct_users=len({e.user for e in items}),
                first_seen=_fmt(items[0].ts),
                last_seen=_fmt(items[-1].ts),
            ))
    report.brute_force.sort(key=lambda b: (-b.failures, b.ip))

    for login in accepted:
        prior = sum(1 for e in by_ip.get(login.ip, []) if e.ts <= login.ts)
        if prior >= threshold:
            report.suspicious_logins.append(SuspiciousLogin(
                ip=login.ip,
                user=clean_text(login.user),
                method=clean_text(login.method, 16),
                time=_fmt(login.ts),
                prior_failures=prior,
            ))
    return report


def format_report(report: Report) -> str:
    lines = [
        f"Events parsed: {report.events}    Failed attempts: {report.failed_attempts}    "
        f"Accepted logins: {report.accepted_logins}    Source IPs with failures: {report.unique_attacker_ips}",
        "",
    ]

    lines.append(
        f"Brute-force sources (>= {report.threshold} failures within {report.window_minutes} min):"
    )
    if report.brute_force:
        lines.append(f"  {'IP':<40}{'FAILS':<8}{'PEAK':<7}{'USERS':<7}FIRST -> LAST")
        for b in report.brute_force:
            lines.append(
                f"  {b.ip:<40}{b.failures:<8}{b.max_in_window:<7}{b.distinct_users:<7}"
                f"{b.first_seen} -> {b.last_seen}"
            )
    else:
        lines.append("  none")

    lines += ["", "Logins that followed many failures from the same IP (review these first):"]
    if report.suspicious_logins:
        for s in report.suspicious_logins:
            lines.append(
                f"  {s.time}  user '{s.user}' via {s.method} from {s.ip} "
                f"after {s.prior_failures} failed attempts"
            )
    else:
        lines.append("  none")

    if report.top_users:
        lines += ["", "Most targeted usernames:"]
        lines += [f"  {name:<24}{count}" for name, count in report.top_users]
    return "\n".join(lines)
