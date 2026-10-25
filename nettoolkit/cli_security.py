"""CLI commands for the security tools (currently: logscan)."""

from __future__ import annotations

import argparse
import json
import sys
import time

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


def cmd_sniff(args: argparse.Namespace) -> int:
    from .sniffer import PcapWriter, Stats, format_summary, make_filter, parse_frame, read_pcap, sniff

    keep = make_filter(args.proto, args.host, args.port)
    stats = Stats()
    shown = 0

    def handle(pkt) -> bool:
        nonlocal shown
        if not keep(pkt):
            return False
        stats.add(pkt)
        if not args.quiet:
            print(f"{time.strftime('%H:%M:%S', time.localtime(pkt.ts))}  {pkt.summary()}", flush=True)
        shown += 1
        return True

    if args.read:
        try:
            for ts, frame in read_pcap(args.read):
                pkt = parse_frame(frame, ts)
                if pkt is not None:
                    handle(pkt)
                if args.count and shown >= args.count:
                    break
        except OSError as exc:
            raise RuntimeError(f"cannot read {args.read}: {exc.strerror or exc}")
        print("\n" + format_summary(stats))
        return 0

    writer = PcapWriter(args.write) if args.write else None
    kept_frames = {}

    def save_frame(ts, frame):
        # Only frames that match the display filter are written to the file.
        if writer is not None:
            pkt = parse_frame(frame, ts)
            if pkt is not None and keep(pkt):
                writer.write(ts, frame)

    if not args.quiet:
        where = args.interface or "all interfaces"
        print(f"Capturing on {where}. Ctrl+C to stop.", file=sys.stderr)
    try:
        for pkt in sniff(args.interface, count=args.count, duration=args.duration, on_frame=save_frame):
            if handle(pkt) and args.count and shown >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if writer is not None:
            writer.close()
    print("\n" + format_summary(stats))
    if args.write:
        print(f"\nSaved to {args.write} (owner-readable only; it may contain sensitive data).")
    return 0


def register(sub) -> None:
    p = sub.add_parser("sniff", help="capture or read packets (needs sudo for live capture)")
    p.add_argument("-i", "--interface", help="interface name, e.g. eth0 (default: all)")
    p.add_argument("-r", "--read", metavar="FILE", help="read a .pcap file instead of capturing")
    p.add_argument("-w", "--write", metavar="FILE", help="save captured packets to a .pcap file")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after this many packets")
    p.add_argument("-d", "--duration", type=float, default=0, help="stop after this many seconds")
    p.add_argument("--proto", help="filter: tcp, udp, icmp, arp or dns")
    p.add_argument("--host", help="filter: packets to or from this IP")
    p.add_argument("--port", type=int, help="filter: packets using this port")
    p.add_argument("-q", "--quiet", action="store_true", help="only print the summary")
    p.set_defaults(func=cmd_sniff)

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
