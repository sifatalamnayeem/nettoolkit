"""Turn `nettool discover --json` / `nettool scan --json` output into a Graphviz diagram.

Host names come from reverse DNS, so anyone who controls a PTR record controls that text.
Everything that goes into the .dot file is therefore reduced to printable ASCII and
escaped, so a hostile name cannot break out of its label and inject graph syntax.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence


def dot_escape(text: str, limit: int = 60) -> str:
    text = re.sub(r"[^\x20-\x7e]", "?", str(text))[:limit]
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _read_json(path: str | Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror or exc}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}")


def load_hosts(path: str | Path) -> List[dict]:
    """Read the output of `nettool discover --json`."""
    data = _read_json(path)
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list (output of `nettool discover --json`)")
    hosts = []
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            ip = str(ipaddress.ip_address(item.get("ip", "")))
        except ValueError:
            continue
        hosts.append({"ip": ip, "hostname": str(item.get("hostname") or "")})
    if not hosts:
        raise ValueError(f"{path}: no hosts found")
    return hosts


def load_scans(paths: Sequence[str | Path]) -> Dict[str, List[dict]]:
    """Read outputs of `nettool scan --json` -> {ip: [open ports]}."""
    scans: Dict[str, List[dict]] = {}
    for path in paths:
        data = _read_json(path)
        if not isinstance(data, dict) or "ip" not in data:
            raise ValueError(f"{path}: expected the output of `nettool scan --json`")
        try:
            ip = str(ipaddress.ip_address(data["ip"]))
        except ValueError:
            raise ValueError(f"{path}: invalid ip")
        scans[ip] = [p for p in data.get("ports", []) if isinstance(p, dict) and p.get("open")]
    return scans


def guess_gateway(hosts: Sequence[dict]) -> Optional[str]:
    for h in hosts:
        if h["ip"].endswith(".1"):
            return h["ip"]
    return None


def build_dot(hosts: Sequence[dict], scans: Optional[Dict[str, List[dict]]] = None,
              gateway: Optional[str] = None, title: str = "Network map") -> str:
    scans = scans or {}
    ips = [h["ip"] for h in hosts]
    gateway = gateway or guess_gateway(hosts)
    if gateway is not None:
        gateway = str(ipaddress.ip_address(gateway))

    lines = [
        "graph network {",
        f'  label="{dot_escape(title)}"; labelloc=t; fontname="Helvetica"; fontsize=18; dpi=144;',
        '  node [fontname="Helvetica", fontsize=11, shape=box, style="rounded,filled", fillcolor="#eef3fb"];',
        '  edge [color="#7a8699"];',
        '  lan [label="LAN switch", shape=ellipse, fillcolor="#dfe6f0"];',
    ]
    if gateway:
        lines.append('  internet [label="Internet", shape=ellipse, style="dashed,filled", fillcolor="#ffffff"];')
        if gateway not in ips:
            lines.append(f'  "{dot_escape(gateway)}" [label="{dot_escape(gateway)}\\nGateway", fillcolor="#ffe9c7"];')
        lines.append(f'  internet -- "{dot_escape(gateway)}";')
        lines.append(f'  "{dot_escape(gateway)}" -- lan;')

    for h in sorted(hosts, key=lambda x: ipaddress.ip_address(x["ip"])):
        ip = h["ip"]
        parts = [dot_escape(ip)]
        if h["hostname"]:
            parts.append(dot_escape(h["hostname"]))
        ports = scans.get(ip, [])
        if ports:
            shown = ", ".join(f'{p.get("port")}/{dot_escape(p.get("service", "?"), 12)}' for p in ports[:6])
            parts.append("open: " + shown + (" ..." if len(ports) > 6 else ""))
        fill = "#ffe9c7" if ip == gateway else ("#fde2e2" if ports else "#eef3fb")
        label = "\\n".join(parts) + ("\\nGateway" if ip == gateway else "")
        lines.append(f'  "{dot_escape(ip)}" [label="{label}", fillcolor="{fill}"];')
        if ip != gateway:                       # the gateway is already linked to the LAN above
            lines.append(f'  lan -- "{dot_escape(ip)}";')
    lines.append("}")
    return "\n".join(lines) + "\n"
