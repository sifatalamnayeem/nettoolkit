"""CLI commands for the security tools (currently: logscan)."""

from __future__ import annotations

import argparse
import json
import sys

from .loganalyzer import analyze, format_report, parse_lines


def cmd_logscan(args: argparse.Namespace) -> int:
    try:
        if args.logfile == "-":
            events = list(parse_lines(sys.stdin, year=args.year))
        else:
            with open(args.logfile, encoding="utf-8", errors="replace") as fh:
                events = list(parse_lines(fh, year=args.year))
    except PermissionError:
        raise RuntimeError(
            f"permission denied reading {args.logfile} "
            "(auth logs usually need sudo, or add your user to the 'adm' group)"
        )
    except OSError as exc:
        raise RuntimeError(f"cannot read {args.logfile}: {exc.strerror or exc}")

    report = analyze(events, threshold=args.threshold, window_minutes=args.window, top=args.top)

    if args.ips_only:
        for b in report.brute_force:
            print(b.ip)
        return 0
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    if report.events == 0:
        print("No sshd login events found. Is this an auth.log / secure file?", file=sys.stderr)
    print(format_report(report))
    return 0


def register(sub) -> None:
    p = sub.add_parser("logscan", help="find brute-force attempts in an SSH auth log")
    p.add_argument("logfile", help="e.g. /var/log/auth.log (Debian/Ubuntu) or /var/log/secure; '-' for stdin")
    p.add_argument("--threshold", type=int, default=5, help="failures within the window to flag an IP (default 5)")
    p.add_argument("--window", type=int, default=10, help="window in minutes (default 10)")
    p.add_argument("--top", type=int, default=10, help="how many top entries to list")
    p.add_argument("--year", type=int, help="year for logs without one (default: inferred)")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--ips-only", action="store_true",
                   help="print only flagged IPs, one per line (review before blocking anything)")
    p.set_defaults(func=cmd_logscan)
