"""SQLite storage shared by the monitor, speed logger and (later) the dashboard.

The database lives at ~/.nettoolkit/data.db unless NETTOOL_DB is set.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    target TEXT NOT NULL,
    kind TEXT NOT NULL,
    up INTEGER NOT NULL,
    latency_ms REAL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_target_ts ON checks(target, ts);

CREATE TABLE IF NOT EXISTS speed (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ping_ms REAL,
    download_mbps REAL,
    upload_mbps REAL,
    server TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_db_path() -> Path:
    env = os.environ.get("NETTOOL_DB")
    return Path(env) if env else Path.home() / ".nettoolkit" / "data.db"


def connect(path: Optional[str | Path] = None) -> sqlite3.Connection:
    if str(path) == ":memory:":
        conn = sqlite3.connect(":memory:")
    else:
        db_path = Path(path) if path else default_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


# ---- uptime checks -------------------------------------------------------

def save_check(conn, ts, target, kind, up, latency_ms, detail) -> None:
    conn.execute(
        "INSERT INTO checks (ts, target, kind, up, latency_ms, detail) VALUES (?,?,?,?,?,?)",
        (ts, target, kind, 1 if up else 0, latency_ms, detail),
    )
    conn.commit()


def latest_checks(conn) -> List[sqlite3.Row]:
    """Most recent check for every target."""
    return conn.execute(
        "SELECT * FROM checks WHERE id IN (SELECT MAX(id) FROM checks GROUP BY target) "
        "ORDER BY target"
    ).fetchall()


def uptime_summary(conn, hours: int = 24) -> List[sqlite3.Row]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    return conn.execute(
        "SELECT target, kind, COUNT(*) AS checks, "
        "ROUND(100.0 * AVG(up), 2) AS uptime_pct, "
        "ROUND(AVG(latency_ms), 1) AS avg_latency_ms "
        "FROM checks WHERE ts >= ? GROUP BY target ORDER BY target",
        (cutoff,),
    ).fetchall()


# ---- speed log -----------------------------------------------------------

def save_speed(conn, ts, ping_ms, download_mbps, upload_mbps, server) -> None:
    conn.execute(
        "INSERT INTO speed (ts, ping_ms, download_mbps, upload_mbps, server) VALUES (?,?,?,?,?)",
        (ts, ping_ms, download_mbps, upload_mbps, server),
    )
    conn.commit()


def recent_speed(conn, limit: int = 20) -> List[sqlite3.Row]:
    rows = conn.execute(
        "SELECT * FROM speed ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return list(reversed(rows))


def speed_averages(conn) -> Optional[sqlite3.Row]:
    row = conn.execute(
        "SELECT COUNT(*) AS runs, ROUND(AVG(ping_ms),1) AS ping_ms, "
        "ROUND(AVG(download_mbps),2) AS download_mbps, "
        "ROUND(AVG(upload_mbps),2) AS upload_mbps FROM speed"
    ).fetchone()
    return row if row and row["runs"] else None
