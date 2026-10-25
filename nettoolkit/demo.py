"""Synthetic data so the dashboard can be shown (and screenshotted) right away."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def seed(conn, days: int = 3, seed_value: int = 42) -> None:
    """Fill the database with `days` of fake monitor and speed-test history."""
    rng = random.Random(seed_value)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(days=days)

    # (name, kind, base latency ms, outage as (start_fraction, end_fraction) or None)
    targets = [
        ("Google", "http", 38, None),
        ("My website", "http", 120, (0.955, 0.965)),
        ("Office SSH", "tcp", 22, (0.88, 0.91)),
        ("Website certificate", "ssl", 210, None),
    ]
    check_rows = []
    steps = days * 24 * 12  # one check every 5 minutes
    for name, kind, base, outage in targets:
        for i in range(steps + 1):
            frac = i / steps
            ts = _iso(start + timedelta(minutes=5 * i))
            down = outage is not None and outage[0] <= frac <= outage[1]
            if down:
                check_rows.append((ts, name, kind, 0, None, "timed out"))
                continue
            latency = round(max(3.0, rng.gauss(base, base * 0.15)), 1)
            detail = "certificate expires in 61 days" if kind == "ssl" else (
                "HTTP 200" if kind == "http" else "port open")
            check_rows.append((ts, name, kind, 1, latency, detail))
    conn.executemany(
        "INSERT INTO checks (ts, target, kind, up, latency_ms, detail) VALUES (?,?,?,?,?,?)",
        check_rows,
    )

    speed_rows = []
    for i in range(days * 24 + 1):
        t = start + timedelta(hours=i)
        evening_dip = 0.65 if 19 <= (t.hour + 6) % 24 <= 23 else 1.0  # busy hours (UTC+6)
        speed_rows.append((
            _iso(t),
            round(max(5.0, rng.gauss(24, 4)), 1),
            round(max(2.0, rng.gauss(88, 8) * evening_dip), 2),
            round(max(1.0, rng.gauss(41, 4) * evening_dip), 2),
            "https://speed.cloudflare.com",
        ))
    conn.executemany(
        "INSERT INTO speed (ts, ping_ms, download_mbps, upload_mbps, server) VALUES (?,?,?,?,?)",
        speed_rows,
    )
    conn.commit()
