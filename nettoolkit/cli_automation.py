"""CLI: nettool netauto backup | run (needs Netmiko: pip install 'nettoolkit[automation]')."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .automation import (
    backup_devices, credentials_from_env, load_inventory, netmiko_connect, run_commands,
)


def make_connect():
    """Build the connect(device) function. Tests replace this with a fake."""
    creds = credentials_from_env()
    return lambda device: netmiko_connect(device, creds)


def _select(devices, only):
    if not only:
        return devices
    wanted = set(only)
    chosen = [d for d in devices if d.name in wanted]
    missing = wanted - {d.name for d in chosen}
    if missing:
        raise ValueError(f"not in inventory: {', '.join(sorted(missing))}")
    return chosen


def cmd_backup(args: argparse.Namespace) -> int:
    devices = _select(load_inventory(args.inventory), args.device)
    results = backup_devices(devices, make_connect(), args.output, args.command, args.workers)

    if args.json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
    else:
        for r in results:
            if r.status == "failed":
                print(f"FAILED     {r.device:<20}{r.error}")
            elif r.status == "changed":
                print(f"CHANGED    {r.device:<20}+{r.added} -{r.removed} lines  {r.path}")
                if args.show_diff:
                    print("\n".join("    " + ln for ln in r.diff.splitlines()))
            else:
                print(f"{r.status.upper():<10} {r.device:<20}{r.path or ''}")
        print(f"\nBackups are stored in {Path(args.output).resolve()} (owner-only files; keep them out of git).")
    return 1 if any(r.status == "failed" for r in results) else 0


def cmd_run(args: argparse.Namespace) -> int:
    devices = _select(load_inventory(args.inventory), args.device)
    config_mode = bool(args.config_file)
    if config_mode:
        try:
            commands = Path(args.config_file).read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ValueError(f"cannot read {args.config_file}: {exc.strerror or exc}")
    else:
        commands = args.command
        if not commands:
            raise ValueError("give at least one --command (or --config-file for changes)")

    if config_mode and args.apply:
        print(f"About to send configuration to {len(devices)} device(s): "
              f"{', '.join(d.name for d in devices)}", file=sys.stderr)
        if not args.yes:
            if not sys.stdin.isatty():
                raise ValueError("refusing to apply changes without a terminal; pass --yes to confirm")
            if input("Type 'yes' to continue: ").strip().lower() != "yes":
                print("Cancelled.", file=sys.stderr)
                return 1

    connect = make_connect() if (not config_mode or args.apply) else (lambda d: None)
    results = run_commands(devices, connect, commands, config_mode, args.apply, args.workers)
    for r in results:
        header = f"=== {r.device} " + ("" if r.ok else "(FAILED) ") + "=" * 20
        print(header)
        print(r.output if r.ok else r.error)
    if config_mode and not args.apply:
        print("\nDry run only. Nothing was sent. Re-run with --apply to push these changes.", file=sys.stderr)
    return 0 if all(r.ok for r in results) else 1


def register(sub) -> None:
    na = sub.add_parser("netauto", help="network automation: config backup and bulk commands (Netmiko)")
    nsub = na.add_subparsers(dest="netauto_cmd", required=True)

    def common(p):
        p.add_argument("-i", "--inventory", required=True, help="inventory JSON (see examples/inventory.example.json)")
        p.add_argument("-d", "--device", action="append", help="limit to this device name (repeatable)")
        p.add_argument("--workers", type=int, default=5, help="parallel connections (default 5)")

    p = nsub.add_parser("backup", help="save running configs and show what changed")
    common(p)
    p.add_argument("-o", "--output", default="backups", help="backup folder (default ./backups)")
    p.add_argument("--command", default="show running-config", help="command that prints the config")
    p.add_argument("--show-diff", action="store_true", help="print the diff for changed devices")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_backup)

    p = nsub.add_parser("run", help="run show commands, or push config changes (dry run by default)")
    common(p)
    p.add_argument("-c", "--command", action="append", help="read-only command (repeatable)")
    p.add_argument("--config-file", help="file with one configuration command per line")
    p.add_argument("--apply", action="store_true", help="actually send --config-file (otherwise dry run)")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p.set_defaults(func=cmd_run)
