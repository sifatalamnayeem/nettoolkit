"""Live capture on Linux (AF_PACKET raw socket). Needs root or CAP_NET_RAW.

Only capture on networks you own or are authorised to monitor. This sees frames to and
from this machine on the chosen interface (it does not switch the card into promiscuous
mode), records what it decodes, and does not reassemble streams or decrypt anything.
"""

from __future__ import annotations

import socket
import time
from typing import Callable, Iterator, Optional

from .packets import Packet, parse_frame

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4          # sll_pkttype value from <linux/if_packet.h>: frame sent by this host


class CaptureError(RuntimeError):
    """Raised for problems the user can fix (no permission, unknown interface, wrong OS)."""


def open_socket(interface: Optional[str]) -> socket.socket:
    if not hasattr(socket, "AF_PACKET"):
        raise CaptureError("live capture is only supported on Linux; on other systems use "
                           "`nettool sniff -r file.pcap` to read a capture made with tcpdump or Wireshark")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        if interface:
            sock.bind((interface, 0))
    except PermissionError:
        raise CaptureError("permission denied: live capture needs sudo (raw sockets require root or CAP_NET_RAW)")
    except OSError as exc:
        raise CaptureError(f"cannot capture on '{interface or 'all interfaces'}': {exc.strerror or exc}")
    sock.settimeout(0.5)          # wake up regularly so Ctrl+C and --duration are honoured
    return sock


def sniff(
    interface: Optional[str] = None,
    count: int = 0,
    duration: float = 0,
    on_frame: Optional[Callable[[float, bytes], None]] = None,
) -> Iterator[Packet]:
    """Yield decoded packets until `duration` seconds pass (0 = until the caller stops).

    `on_frame(ts, raw_frame)` is called for every frame before decoding, so a caller can save the
    raw bytes. `count` is accepted but not enforced here: the caller counts only the packets that
    pass its own filter and stops iterating, which matches how `tcpdump -c` behaves.
    """
    sock = open_socket(interface)
    deadline = time.monotonic() + duration if duration else None
    try:
        while deadline is None or time.monotonic() < deadline:
            try:
                raw, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            # On the loopback interface the kernel hands over every frame twice (once as outgoing,
            # once as incoming). Keep one copy, like tcpdump does. Real NICs keep both directions.
            if addr[0] == "lo" and addr[2] == PACKET_OUTGOING:
                continue
            ts = time.time()
            if on_frame is not None:
                on_frame(ts, raw)
            pkt = parse_frame(raw, ts)
            if pkt is not None:
                yield pkt
    finally:
        sock.close()
