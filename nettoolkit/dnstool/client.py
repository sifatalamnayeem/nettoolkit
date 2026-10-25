"""A small DNS client (standard library only): A, AAAA, MX, NS, TXT, CNAME, PTR.

Replies come from the network, so the parser treats them as hostile: it checks the
transaction ID and sender, follows name-compression pointers with a hop limit, and
raises DNSError (never IndexError or an endless loop) on anything malformed.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import socket
import statistics
import struct
import time
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
_QTYPE_NAMES = {v: k for k, v in QTYPES.items()}
RCODES = {1: "format error", 2: "server failure", 3: "name does not exist (NXDOMAIN)",
          4: "not implemented", 5: "refused"}
PUBLIC_RESOLVERS = {"Google": "8.8.8.8", "Cloudflare": "1.1.1.1", "Quad9": "9.9.9.9"}
MAX_POINTER_HOPS = 20
_LABEL_OK = re.compile(r"^[A-Za-z0-9_*-]+$")   # letters, digits, hyphen, underscore (SRV/DKIM), wildcard


class DNSError(Exception):
    pass


@dataclass
class Answer:
    name: str
    type: str
    ttl: int
    value: str

    def to_dict(self) -> dict:
        return asdict(self)


def clean(text: bytes) -> str:
    """Printable ASCII only (TXT records and names are attacker-controlled)."""
    return "".join(chr(b) if 32 <= b < 127 else "?" for b in text)


# ---- building the question -----------------------------------------------

def encode_name(name: str) -> bytes:
    name = name.strip().rstrip(".")
    if not name:
        raise ValueError("domain name is empty")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"invalid domain name: {name!r}")
    labels = ascii_name.split(".")
    if (len(ascii_name) > 253
            or any(not 1 <= len(l) <= 63 for l in labels)
            or any(not _LABEL_OK.match(l) for l in labels)):
        raise ValueError(f"invalid domain name: {name!r}")
    return b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"


def build_query(name: str, qtype: int, txid: Optional[int] = None) -> Tuple[int, bytes]:
    txid = secrets.randbelow(65536) if txid is None else txid
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)   # recursion desired
    return txid, header + encode_name(name) + struct.pack("!HH", qtype, 1)


# ---- reading the reply ----------------------------------------------------

def read_name(msg: bytes, pos: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) name. Returns (name, position after it in the record)."""
    labels: List[str] = []
    end: Optional[int] = None
    hops = 0
    while True:
        if pos >= len(msg):
            raise DNSError("truncated name")
        size = msg[pos]
        if size == 0:
            pos += 1
            break
        if size & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise DNSError("truncated compression pointer")
            hops += 1
            if hops > MAX_POINTER_HOPS:
                raise DNSError("compression pointer loop")
            if end is None:
                end = pos + 2
            pos = ((size & 0x3F) << 8) | msg[pos + 1]
            continue
        if size & 0xC0:
            raise DNSError("unsupported label type")
        if pos + 1 + size > len(msg):
            raise DNSError("label runs past end of message")
        labels.append(clean(msg[pos + 1: pos + 1 + size]))
        pos += 1 + size
        if len(labels) > 127:
            raise DNSError("name too long")
    return ".".join(labels) or ".", (end if end is not None else pos)


def _format_rdata(msg: bytes, rtype: int, start: int, length: int) -> str:
    end = start + length
    data = msg[start:end]
    if rtype == 1 and length == 4:
        return str(ipaddress.IPv4Address(data))
    if rtype == 28 and length == 16:
        return str(ipaddress.IPv6Address(data))
    if rtype in (2, 5, 12):
        return read_name(msg, start)[0]
    if rtype == 15 and length >= 3:
        pref = struct.unpack("!H", data[:2])[0]
        return f"{pref} {read_name(msg, start + 2)[0]}"
    if rtype == 16:
        parts, i = [], 0
        while i < len(data):
            size = data[i]
            if i + 1 + size > len(data):
                raise DNSError("truncated TXT record")
            parts.append(clean(data[i + 1: i + 1 + size]))
            i += 1 + size
        return "".join(parts)
    return data.hex()


def parse_response(msg: bytes, txid: int) -> Tuple[List[Answer], bool]:
    """Return (answers, truncated). Raises DNSError for errors and mismatched replies."""
    if len(msg) < 12:
        raise DNSError("reply too short")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if rid != txid:
        raise DNSError("transaction ID mismatch")
    if not flags & 0x8000:
        raise DNSError("not a response")
    rcode = flags & 0x0F
    if rcode:
        raise DNSError(RCODES.get(rcode, f"server returned error code {rcode}"))
    truncated = bool(flags & 0x0200)

    pos = 12
    for _ in range(qd):
        _, pos = read_name(msg, pos)
        pos += 4
    answers: List[Answer] = []
    for _ in range(min(an, 100)):
        name, pos = read_name(msg, pos)
        if pos + 10 > len(msg):
            raise DNSError("truncated record header")
        rtype, _cls, ttl, rdlen = struct.unpack("!HHIH", msg[pos: pos + 10])
        pos += 10
        if pos + rdlen > len(msg):
            raise DNSError("record data runs past end of message")
        answers.append(Answer(name, _QTYPE_NAMES.get(rtype, f"TYPE{rtype}"), ttl,
                              _format_rdata(msg, rtype, pos, rdlen)))
        pos += rdlen
    return answers, truncated


# ---- talking to a server --------------------------------------------------

def _udp(query: bytes, server: str, port: int, timeout: float, txid: int) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (server, port))
        deadline = time.monotonic() + timeout
        while True:
            sock.settimeout(max(deadline - time.monotonic(), 0.001))
            try:
                data, sender = sock.recvfrom(4096)
            except socket.timeout:
                raise DNSError(f"no reply from {server} within {timeout:g}s")
            # Ignore packets from other hosts or with the wrong ID (spoofing attempts, late replies)
            if sender[0] == server and len(data) >= 2 and struct.unpack("!H", data[:2])[0] == txid:
                return data
            if time.monotonic() >= deadline:
                raise DNSError(f"no valid reply from {server}")


def _tcp(query: bytes, server: str, port: int, timeout: float) -> bytes:
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            head = _recv_exact(sock, 2)
            return _recv_exact(sock, struct.unpack("!H", head)[0])
    except OSError as exc:
        raise DNSError(f"TCP query to {server} failed: {exc.strerror or exc}")


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise DNSError("connection closed early")
        buf += chunk
    return buf


def default_resolver() -> str:
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1].split("%")[0]
    except OSError:
        pass
    return "1.1.1.1"


def lookup(name: str, qtype: str = "A", server: Optional[str] = None,
           port: int = 53, timeout: float = 3.0) -> Tuple[List[Answer], float]:
    """Resolve `name`. Returns (answers, milliseconds). Raises DNSError / ValueError."""
    qtype = qtype.upper()
    if qtype not in QTYPES:
        raise ValueError(f"unsupported record type '{qtype}' (use: {', '.join(QTYPES)})")
    if qtype == "PTR":
        try:
            name = ipaddress.ip_address(name).reverse_pointer
        except ValueError:
            pass  # already a reverse name
    server = server or default_resolver()
    try:
        ipaddress.ip_address(server)
    except ValueError:
        raise ValueError(f"resolver must be an IP address, got '{server}'")

    txid, query = build_query(name, QTYPES[qtype])
    start = time.perf_counter()
    try:
        data = _udp(query, server, port, timeout, txid)
    except OSError as exc:
        raise DNSError(f"cannot reach {server}: {exc.strerror or exc}")
    answers, truncated = parse_response(data, txid)
    if truncated:                                   # reply did not fit in UDP: ask again over TCP
        answers, _ = parse_response(_tcp(query, server, port, timeout), txid)
    return answers, round((time.perf_counter() - start) * 1000, 1)


def compare_resolvers(name: str, resolvers: Optional[Dict[str, str]] = None,
                      rounds: int = 3, timeout: float = 2.0, port: int = 53) -> List[dict]:
    """Time the same lookup against several resolvers; the median of `rounds` tries is reported."""
    results = []
    for label, ip in (resolvers or PUBLIC_RESOLVERS).items():
        times, error = [], ""
        for _ in range(rounds):
            try:
                _, ms = lookup(name, "A", ip, port=port, timeout=timeout)
                times.append(ms)
            except (DNSError, ValueError) as exc:
                error = str(exc)
        results.append({
            "resolver": label, "ip": ip,
            "median_ms": round(statistics.median(times), 1) if times else None,
            "ok": len(times), "tries": rounds, "error": "" if times else error,
        })
    return sorted(results, key=lambda r: (r["median_ms"] is None, r["median_ms"] or 0))
