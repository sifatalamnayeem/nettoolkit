"""Live capture (Linux AF_PACKET) and a minimal pcap writer.

Capturing needs root (or CAP_NET_RAW). Only capture on networks you own or are
authorised to monitor. This module records headers and the first bytes of each
frame; it does not reassemble streams or decrypt anything.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Callable, Iterator, Optional

from .packets import Packet, parse_frame

ETH_P_ALL = 0x0003
PCAP_MAGIC, LINKTYPE_ETHERNET = 0xA1B2C3D4, 1


class CaptureError(RuntimeError):
    pass


class PcapWriter:
    """Writes classic pcap files that Wireshark and tcpdump can open."""

    def __init__(self, path: str, snaplen: int = 65535):
        self._fh = open(path, "wb")
        self.snaplen = snaplen
        self._fh.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, snaplen, LINKTYPE_ETHERNET))

    def write(self, frame: bytes, ts: Optional[float] = None) -> None:
        ts = time.time() if ts is None else ts
        data = frame[: self.snaplen]
        sec = int(ts)
        self._fh.write(struct.pack("<IIII", sec, int((ts - sec) * 1_000_000), len(data), len(frame)))
        self._fh.write(data)

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def make_filter(
    protocol: Optional[str] = None, host: Optional[str] = None, port: Optional[int] = None
) -> Callable[[Packet], bool]:
    """Simple post-capture filter (not BPF): all given conditions must match."""
    proto = protocol.upper() if protocol else None

    def accept(pkt: Packet) -> bool:
        if proto and pkt.protocol.upper() != proto and not (proto == "UDP" and pkt.protocol == "DNS"):
            return False
        if host and host not in (pkt.src, pkt.dst):
            return False
        if port is not None and port not in (pkt.src_port, pkt.dst_port):
            return False
        return True

    return accept


def open_socket(interface: Optional[str]) -> socket.socket:
    if not hasattr(socket, "AF_PACKET"):
        raise CaptureError("live capture is only supported on Linux (AF_PACKET)")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        if interface:
            sock.bind((interface, 0))
    except PermissionError:
        raise CaptureError("permission denied: run with sudo (raw sockets need root or CAP_NET_RAW)")
    except OSError as exc:
        raise CaptureError(f"cannot open capture on '{interface or 'all interfaces'}': {exc.strerror or exc}")
    sock.settimeout(0.5)
    return sock


def frames(sock: socket.socket, duration: Optional[float] = None) -> Iterator[bytes]:
    """Yield raw frames until `duration` seconds pass (or forever when None)."""
    deadline = None if duration is None else time.monotonic() + duration
    while deadline is None or time.monotonic() < deadline:
        try:
            yield sock.recv(65535)
        except socket.timeout:
            continue


def capture(
    interface: Optional[str] = None,
    count: Optional[int] = None,
    duration: Optional[float] = None,
    accept: Callable[[Packet], bool] = lambda p: True,
    pcap_path: Optional[str] = None,
) -> Iterator[Packet]:
    sock = open_socket(interface)
    writer = PcapWriter(pcap_path) if pcap_path else None
    seen = 0
    try:
        for raw in frames(sock, duration):
            pkt = parse_frame(raw)
            if not accept(pkt):
                continue
            if writer:
                writer.write(raw)
            seen += 1
            yield pkt
            if count is not None and seen >= count:
                break
    finally:
        sock.close()
        if writer:
            writer.close()
