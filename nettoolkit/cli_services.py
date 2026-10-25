"""CLI commands for the long-running tools: monitor, speedlog, alert-test."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time

from . import storage
from .alerts import notifier_from_env
from .monitor import Monitor, load_config
from .speedlog import DEFAULT_SERVER, run_speedtest


def _fmt(value, suffix="") -> str:
    return "-" if value is None else f"{value}{suffix}"


# ---- monitor -------------------------------------------------------------

def _print_results(results) -> None:
    stamp = time.strftime("%H:%M:%S")
    for r in results:
        icon = "UP  " if r.up else "DOWN"
        print(f"{stamp}  {icon}  {r.target:<28}{_fmt(r.latency_ms, ' ms'):<12}{r.detail}")
    sys.stdout.flush()


def cmd_monitor_run(args: argparse.Namespace) -> int:
    targets, settings = load_config(args.config)
    interval = args.interval or settings["interval"]
    threshold = args.threshold or settings["fail_threshold"]

    notifier, is_telegram = notifier_from_env()
    if not is_telegram:
        print(
            "note: Telegram not configured (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID); "
            "alerts will print here instead.",
            file=sys.stderr,
        )

    conn = storage.connect(args.db)
    monitor = Monitor(targets, notifier=notifier, conn=conn, fail_threshold=threshold)

    if args.once:
        results = monitor.run_once()
        _print_results(results)
        return 0 if all(r.up for r in results) else 1

    print(f"Monitoring {len(targets)} target(s) every {interval}s. Ctrl+C to stop.")
    monitor.run_forever(interval, on_results=_print_results)
    return 0


def cmd_monitor_status(args: argparse.Namespace) -> int:
    conn = storage.connect(args.db)
    latest = {r["target"]: r for r in storage.latest_checks(conn)}
    summary = storage.uptime_summary(conn, hours=args.hours)

    if args.json:
        print(json.dumps(
            [
                {**dict(s), "currently_up": bool(latest[s["target"]]["up"]),
                 "last_check": latest[s["target"]]["ts"]}
                for s in summary if s["target"] in latest
            ],
            indent=2,
        ))
        return 0

    if not summary:
        print(f"No checks recorded in the last {args.hours}h. Run `nettool monitor run` first.")
        return 0
    print(f"{'TARGET':<28}{'NOW':<6}{'UPTIME':<10}{'AVG MS':<10}CHECKS (last {args.hours}h)")
    for s in summary:
        now = "up" if latest[s["target"]]["up"] else "DOWN"
        print(f"{s['target']:<28}{now:<6}{str(s['uptime_pct']) + '%':<10}"
              f"{_fmt(s['avg_latency_ms']):<10}{s['checks']}")
    return 0


# ---- speedlog ------------------------------------------------------------

def _run_and_save(args):
    result = run_speedtest(
        server=args.server, download_mb=args.size, do_upload=not args.no_upload
    )
    conn = storage.connect(args.db)
    storage.save_speed(
        conn, storage.now_iso(), result.ping_ms, result.download_mbps,
        result.upload_mbps, result.server,
    )
    print(
        f"{time.strftime('%Y-%m-%d %H:%M:%S')}  ping {_fmt(result.ping_ms, ' ms')}  "
        f"down {_fmt(result.download_mbps, ' Mbps')}  up {_fmt(result.upload_mbps, ' Mbps')}"
    )
    sys.stdout.flush()
    return result


def cmd_speed_run(args: argparse.Namespace) -> int:
    _run_and_save(args)
    return 0


def cmd_speed_loop(args: argparse.Namespace) -> int:
    print(f"Logging a speed test every {args.every}s. Ctrl+C to stop.")
    while True:
        try:
            _run_and_save(args)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
        time.sleep(args.every)


def cmd_speed_history(args: argparse.Namespace) -> int:
    conn = storage.connect(args.db)
    rows = storage.recent_speed(conn, args.limit)
    if args.json:
        print(json.dumps([dict(r) for r in rows], indent=2))
        return 0
    if not rows:
        print("No speed tests recorded yet. Run `nettool speedlog run`.")
        return 0
    print(f"{'TIME (UTC)':<22}{'PING':<10}{'DOWN':<14}UP")
    for r in rows:
        print(f"{r['ts'][:19].replace('T', ' '):<22}{_fmt(r['ping_ms'], ' ms'):<10}"
              f"{_fmt(r['download_mbps'], ' Mbps'):<14}{_fmt(r['upload_mbps'], ' Mbps')}")
    avg = storage.speed_averages(conn)
    if avg:
        print(f"\nAverage over {avg['runs']} run(s): ping {_fmt(avg['ping_ms'], ' ms')}, "
              f"down {_fmt(avg['download_mbps'], ' Mbps')}, up {_fmt(avg['upload_mbps'], ' Mbps')}")
    return 0


def cmd_speed_export(args: argparse.Namespace) -> int:
    conn = storage.connect(args.db)
    rows = conn.execute("SELECT ts, ping_ms, download_mbps, upload_mbps, server FROM speed ORDER BY id").fetchall()
    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ts", "ping_ms", "download_mbps", "upload_mbps", "server"])
        writer.writerows([tuple(r) for r in rows])
    print(f"Wrote {len(rows)} row(s) to {args.output}")
    return 0


# ---- alert-test ----------------------------------------------------------

def cmd_alert_test(args: argparse.Namespace) -> int:
    notifier, is_telegram = notifier_from_env()
    if not is_telegram:
        print("Telegram is not configured; set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.",
              file=sys.stderr)
    ok = notifier.send("✅ NetToolkit test alert: Telegram is working.")
    print("Test alert sent." if ok else "Failed to send the test alert.")
    return 0 if ok else 1


# ---- registration --------------------------------------------------------

def register(sub) -> None:
    db_help = "SQLite file (default: ~/.nettoolkit/data.db or $NETTOOL_DB)"

    mon = sub.add_parser("monitor", help="uptime monitor with Telegram alerts")
    msub = mon.add_subparsers(dest="monitor_cmd", required=True)

    p = msub.add_parser("run", help="run checks from a JSON config")
    p.add_argument("-c", "--config", required=True, help="path to monitor.json")
    p.add_argument("--once", action="store_true", help="run one round and exit (exit code 1 if anything is down)")
    p.add_argument("--interval", type=int, help="seconds between rounds (overrides config)")
    p.add_argument("--threshold", type=int, help="failures in a row before alerting (overrides config)")
    p.add_argument("--db", help=db_help)
    p.set_defaults(func=cmd_monitor_run)

    p = msub.add_parser("status", help="show uptime from stored history")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--json", action="store_true")
    p.add_argument("--db", help=db_help)
    p.set_defaults(func=cmd_monitor_status)

    sp = sub.add_parser("speedlog", help="internet speed logger")
    ssub = sp.add_subparsers(dest="speed_cmd", required=True)

    def common(p):
        p.add_argument("--server", default=DEFAULT_SERVER, help="speed test server URL")
        p.add_argument("--size", type=float, default=10, help="download size in MB (default 10)")
        p.add_argument("--no-upload", action="store_true", help="skip the upload test")
        p.add_argument("--db", help=db_help)

    p = ssub.add_parser("run", help="run one speed test and log it")
    common(p)
    p.set_defaults(func=cmd_speed_run)

    p = ssub.add_parser("loop", help="run a speed test repeatedly")
    common(p)
    p.add_argument("--every", type=int, default=3600, help="seconds between tests (default 3600)")
    p.set_defaults(func=cmd_speed_loop)

    p = ssub.add_parser("history", help="show logged results")
    p.add_argument("-n", "--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.add_argument("--db", help=db_help)
    p.set_defaults(func=cmd_speed_history)

    p = ssub.add_parser("export", help="export all results to CSV")
    p.add_argument("output", help="e.g. speed.csv")
    p.add_argument("--db", help=db_help)
    p.set_defaults(func=cmd_speed_export)

    p = sub.add_parser("alert-test", help="send a test alert to Telegram")
    p.set_defaults(func=cmd_alert_test)
