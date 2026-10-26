"""Read and write classic .pcap files (the format Wireshark and tcpdump use)."""

from __future__ import annotations

import os
import struct
from typing import Iterator, Tuple

MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
MAX_RECORD = 262144          # larger "captured length" values mean the file is corrupt or hostile

_READ_FORMATS = {            # first four bytes -> (byte order, seconds per fraction unit)
    bytes.fromhex("d4c3b2a1"): ("<", 1e-6),
    bytes.fromhex("a1b2c3d4"): (">", 1e-6),
    bytes.fromhex("4d3cb2a1"): ("<", 1e-9),
    bytes.fromhex("a1b23c4d"): (">", 1e-9),
}


class PcapWriter:
    """Write frames to a pcap file. The file is owner-only (0600): captures hold other
    people's traffic, which may include passwords and cookies sent without encryption."""

    def __init__(self, path: str, snaplen: int = 65535):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        except OSError as exc:
            raise RuntimeError(f"cannot write {path}: {exc.strerror or exc}")
        try:
            os.fchmod(fd, 0o600)             # also tighten a pre-existing file we are overwriting
        except (AttributeError, OSError):
            pass
        self._fh = os.fdopen(fd, "wb")
        self.snaplen = snaplen
        self._fh.write(struct.pack("<IHHiIII", MAGIC, 2, 4, 0, 0, snaplen, LINKTYPE_ETHERNET))

    def write(self, ts: float, frame: bytes) -> None:
        data = frame[: self.snaplen]
        sec = int(ts)
        self._fh.write(struct.pack("<IIII", sec, int((ts - sec) * 1_000_000), len(data), len(frame)))
        self._fh.write(data)

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def read_pcap(path: str) -> Iterator[Tuple[float, bytes]]:
    """Yield (timestamp, frame) from a pcap file. Raises ValueError for unsupported or corrupt files;
    a file cut off in the middle of its last packet just ends early."""
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            raise ValueError(f"{path} is not a pcap file (too short)")
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            raise ValueError("pcapng files are not supported; convert first: editcap -F pcap in.pcapng out.pcap")
        if head[:4] not in _READ_FORMATS:
            raise ValueError(f"{path} is not a pcap file (bad magic number)")
        order, unit = _READ_FORMATS[head[:4]]
        _major, _minor, _zone, _sigfigs, _snaplen, linktype = struct.unpack(order + "HHiIII", head[4:24])
        if linktype != LINKTYPE_ETHERNET:
            raise ValueError(f"unsupported link type {linktype} (only Ethernet captures can be read)")
        while True:
            record = fh.read(16)
            if len(record) < 16:
                return
            sec, frac, caplen, _orig = struct.unpack(order + "IIII", record)
            if caplen > MAX_RECORD:
                raise ValueError("corrupt pcap: packet record is impossibly large")
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            yield sec + frac * unit, data
