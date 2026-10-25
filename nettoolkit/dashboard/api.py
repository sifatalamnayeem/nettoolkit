"""Read-only queries that feed the dashboard. Each function takes an open connection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from .. import storage


def _cutoff(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")


def overview(conn, hours: int = 24) -> Dict[str, Any]:
    latest = {r["target"]: r for r in storage.latest_checks(conn)}
    summary = {r["target"]: r for r in storage.uptime_summary(conn, hours)}

    targets = []
    for name, row in latest.items():
        s = summary.get(name)
        targets.append({
            "name": name,
            "kind": row["kind"],
            "up": bool(row["up"]),
            "last_check": row["ts"],
            "detail": row["detail"],
            "latency_ms": row["latency_ms"],
            "uptime_pct": s["uptime_pct"] if s else None,
            "avg_latency_ms": s["avg_latency_ms"] if s else None,
            "checks": s["checks"] if s else 0,
        })
    targets.sort(key=lambda t: (t["up"], t["name"]))  # problems first

    speed_latest = storage.recent_speed(conn, 1)
    averages = storage.speed_averages(conn)
    return {
        "hours": hours,
        "generated_at": storage.now_iso(),
        "targets": targets,
        "speed": {
            "latest": dict(speed_latest[0]) if speed_latest else None,
            "averages": dict(averages) if averages else None,
        },
    }


def check_series(conn, target: str, hours: int = 24, max_points: int = 200) -> Dict[str, Any]:
    rows = conn.execute(
        "SELECT ts, up, latency_ms FROM checks WHERE target = ? AND ts >= ? ORDER BY ts",
        (target, _cutoff(hours)),
    ).fetchall()
    if len(rows) > max_points:
        stride = -(-len(rows) // max_points)  # ceil division
        sampled = rows[::stride]
        if sampled[-1] is not rows[-1]:
            sampled.append(rows[-1])
        rows = sampled
    return {
        "target": target,
        "points": [
            {"ts": r["ts"], "up": bool(r["up"]), "latency_ms": r["latency_ms"]} for r in rows
        ],
    }


def speed_series(conn, limit: int = 100) -> Dict[str, Any]:
    return {"points": [dict(r) for r in storage.recent_speed(conn, limit)]}
