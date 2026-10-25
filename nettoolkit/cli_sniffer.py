"""CLI command: nettool sniff"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from .sniffer import summarize
from .sniffer.capture import CaptureError, capture, make_filter


def cmd_sniff(args: argparse.Namespace) -> int:
    if args.count is None and args.duration is None:
        args.count = 50  # safe default so a bare `nettool sniff` stops by itself
    accept = make_filter(args.protocol, args.host, args.port)
    stats = Counter()
    talkers = Counter()

    try:
        print(f"Capturing on {args.interface or 'all interfaces'} (Ctrl+C to stop)...", file=sys.stderr)
        for pkt in capture(args.interface, args.count, args.duration, accept, args.write):
            stats[pkt.protocol or "other"] += 1
            if pkt.src:
                talkers[pkt.src] += 1
            if args.json:
                print(json.dumps(pkt.to_dict()), flush=True)
            else:
                print(summarize(pkt), flush=True)
    except CaptureError as exc:
        raise RuntimeError(str(exc))
    except KeyboardInterrupt:
        pass

    if not args.json:
        total = sum(stats.values())
        print(f"\n{total} packet(s) captured", file=sys.stderr)
        if total:
            print("  by protocol: " + ", ".join(f"{k} {v}" for k, v in stats.most_common()), file=sys.stderr)
            print("  top sources: " + ", ".join(f"{k} ({v})" for k, v in talkers.most_common(3)), file=sys.stderr)
        if args.write:
            print(f"  saved to {args.write} (open it in Wireshark)", file=sys.stderr)
    return 0


def register(sub) -> None:
    p = sub.add_parser("sniff", help="capture and decode packets (Linux, needs sudo)")
    p.add_argument("-i", "--interface", help="e.g. eth0 or wlan0 (default: all)")
    p.add_argument("-c", "--count", type=int, help="stop after N matching packets (default 50 if no --duration)")
    p.add_argument("-d", "--duration", type=float, help="stop after N seconds")
    p.add_argument("--protocol", help="TCP, UDP, ICMP, ARP, DNS ...")
    p.add_argument("--host", help="only packets to or from this IP")
    p.add_argument("--port", type=int, help="only packets using this port")
    p.add_argument("-w", "--write", metavar="FILE.pcap", help="also save raw frames to a pcap file")
    p.add_argument("--json", action="store_true", help="one JSON object per line")
    p.set_defaults(func=cmd_sniff)
