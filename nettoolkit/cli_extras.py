"""CLI commands: dns, vlsm, topology."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys

from .dnstool import QTYPES, DNSError, compare_resolvers, default_resolver, lookup
from .topology import build_dot, load_hosts, load_scans
from .vlsm import parse_requirement, plan_vlsm
from .vlsm.planner import format_plan


# ---- dns ------------------------------------------------------------------

def cmd_dns(args: argparse.Namespace) -> int:
    if args.compare:
        rows = compare_resolvers(args.name, rounds=args.rounds, timeout=args.timeout, port=args.port)
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        print(f"Lookup time for {args.name} (median of {args.rounds}):")
        for r in rows:
            speed = f"{r['median_ms']} ms" if r["median_ms"] is not None else f"failed ({r['error']})"
            print(f"  {r['resolver']:<12}{r['ip']:<16}{speed}")
        return 0 if any(r["median_ms"] is not None for r in rows) else 1

    server = args.server or default_resolver()
    types = [t.upper() for t in (args.type or ["A"])]
    exit_code, output = 0, []
    for qtype in types:
        try:
            answers, ms = lookup(args.name, qtype, server, port=args.port, timeout=args.timeout)
        except DNSError as exc:
            print(f"{qtype}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        output.append({"type": qtype, "ms": ms, "answers": [a.to_dict() for a in answers]})
        if not args.json:
            print(f";; {qtype} {args.name} via {server} in {ms} ms")
            if not answers:
                print("   (no records)")
            for a in answers:
                print(f"   {a.name:<32}{a.ttl:<8}{a.type:<7}{a.value}")
    if args.json:
        print(json.dumps({"server": server, "results": output}, indent=2))
    return exit_code


# ---- vlsm -----------------------------------------------------------------

def cmd_vlsm(args: argparse.Namespace) -> int:
    plan = plan_vlsm(args.network, [parse_requirement(r) for r in args.requirement])
    print(json.dumps(plan.to_dict(), indent=2) if args.json else format_plan(plan))
    return 0


# ---- topology -------------------------------------------------------------

def cmd_topology(args: argparse.Namespace) -> int:
    hosts = load_hosts(args.discover)
    scans = load_scans(args.scan or [])
    dot = build_dot(hosts, scans, args.gateway, args.title)

    if args.output == "-":
        sys.stdout.write(dot)
    else:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(dot)
        print(f"Wrote {args.output} ({len(hosts)} hosts)", file=sys.stderr)

    if args.png:
        exe = shutil.which("dot")
        if not exe:
            raise RuntimeError("Graphviz 'dot' not found. Install Graphviz, or paste the .dot file into an online viewer.")
        try:
            subprocess.run([exe, "-Tpng", "-o", args.png], input=dot.encode(), check=True, timeout=60)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            raise RuntimeError(f"Graphviz failed: {type(exc).__name__}")
        print(f"Wrote {args.png}", file=sys.stderr)
    return 0


def register(sub) -> None:
    p = sub.add_parser("dns", help="DNS lookups (A, AAAA, MX, NS, TXT, CNAME, PTR) and resolver speed comparison")
    p.add_argument("name", help="domain, or an IP address for -t PTR")
    p.add_argument("-t", "--type", action="append", choices=list(QTYPES), type=str.upper, help="record type (repeatable)")
    p.add_argument("-s", "--server", help="resolver IP (default: your system resolver)")
    p.add_argument("--port", type=int, default=53, help="resolver port (default 53)")
    p.add_argument("--compare", action="store_true", help="compare Google, Cloudflare and Quad9 speed")
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_dns)

    p = sub.add_parser("vlsm", help="plan subnets of different sizes from one network block")
    p.add_argument("network", help="e.g. 192.168.10.0/24")
    p.add_argument("-r", "--requirement", action="append", required=True, metavar="NAME:HOSTS",
                   help="department and hosts needed, e.g. -r Sales:50 -r IT:20 (repeatable)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_vlsm)

    p = sub.add_parser("topology", help="draw a network map (Graphviz) from discover/scan JSON")
    p.add_argument("--discover", required=True, metavar="FILE", help="output of: nettool discover CIDR --json")
    p.add_argument("--scan", action="append", metavar="FILE", help="output of: nettool scan HOST --json (repeatable)")
    p.add_argument("--gateway", help="gateway IP (default: the host ending in .1)")
    p.add_argument("--title", default="Network map")
    p.add_argument("-o", "--output", default="network.dot", help="DOT file, or - for stdout")
    p.add_argument("--png", metavar="FILE", help="also render a PNG (needs Graphviz installed)")
    p.set_defaults(func=cmd_topology)
