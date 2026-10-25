"""Command line entry point: `nettool <command>`."""

from __future__ import annotations

import argparse
import json
import socket
import sys

from . import __version__, cli_services
from .scanner import discover_hosts, scan_ports
from .scanner.scanner import parse_ports
from .subnet import calculate, split_subnet


def _print_json(data) -> None:
    print(json.dumps(data, indent=2))


def cmd_subnet(args: argparse.Namespace) -> int:
    info = calculate(args.cidr)
    if args.split:
        subnets = split_subnet(args.cidr, args.split)
        if args.json:
            _print_json({"network": info.to_dict(), "subnets": subnets})
        else:
            print(f"{info.network}/{info.prefix_length} -> {len(subnets)} subnets of /{args.split}:")
            for s in subnets:
                print(f"  {s}")
        return 0

    if args.json:
        _print_json(info.to_dict())
        return 0

    rows = [
        ("Network", f"{info.network}/{info.prefix_length}"),
        ("Netmask", info.netmask),
        ("Wildcard", info.wildcard),
        ("Broadcast", info.broadcast or "n/a (IPv6)"),
        ("First host", info.first_host),
        ("Last host", info.last_host),
        ("Total addresses", f"{info.total_addresses:,}"),
        ("Usable hosts", f"{info.usable_hosts:,}"),
        ("Private", "yes" if info.is_private else "no"),
    ]
    for label, value in rows:
        print(f"{label:<16}{value}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    if args.ports == "common":
        ports = None
    else:
        ports = parse_ports(args.ports)

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"error: cannot resolve host '{args.host}'", file=sys.stderr)
        return 2

    results = scan_ports(ip, ports, timeout=args.timeout, only_open=not args.all)
    if args.json:
        _print_json({"host": args.host, "ip": ip, "ports": [r.to_dict() for r in results]})
        return 0

    print(f"Scan report for {args.host} ({ip})")
    if not results:
        print("No open ports found.")
        return 0
    print(f"{'PORT':<8}{'STATE':<8}SERVICE")
    for r in results:
        state = "open" if r.open else "closed"
        print(f"{r.port:<8}{state:<8}{r.service}")
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    hosts = discover_hosts(
        args.cidr, timeout=args.timeout, resolve_names=not args.no_dns
    )
    if args.json:
        _print_json([h.to_dict() for h in hosts])
        return 0

    print(f"{len(hosts)} host(s) up in {args.cidr}")
    for h in hosts:
        print(f"  {h.ip:<16}{h.hostname or ''}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nettool", description="NetToolkit: small networking utilities."
    )
    parser.add_argument("--version", action="version", version=f"nettool {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("subnet", help="subnet calculator")
    p.add_argument("cidr", help="e.g. 192.168.1.10/24")
    p.add_argument("--split", type=int, metavar="PREFIX", help="split into /PREFIX subnets")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.set_defaults(func=cmd_subnet)

    p = sub.add_parser("scan", help="TCP port scan a host (only scan what you own)")
    p.add_argument("host", help="hostname or IP")
    p.add_argument("-p", "--ports", default="common", help="'common', '22,80', or '1-1024'")
    p.add_argument("-t", "--timeout", type=float, default=0.5)
    p.add_argument("--all", action="store_true", help="also show closed ports")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("discover", help="ping sweep a network for live hosts")
    p.add_argument("cidr", help="e.g. 192.168.0.0/24")
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("--no-dns", action="store_true", help="skip reverse DNS lookups")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.set_defaults(func=cmd_discover)

    cli_services.register(sub)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
