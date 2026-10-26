import os
import random
import socket
import stat
import struct
import tempfile
import threading
import time

import pytest

import nettoolkit.sniffer as sniffer_pkg
import nettoolkit.sniffer.capture as capture_mod
from nettoolkit.cli import main
from nettoolkit.sniffer import (CaptureError, PcapWriter, Stats, format_summary, make_filter,
                                parse_frame, read_pcap, sniff)
from nettoolkit.sniffer.packets import parse_dns, safe_text

ETH = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566")   # dst, src


# ---- frame builders -------------------------------------------------------

def ipv4(proto, src, dst, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return ETH + struct.pack("!H", 0x0800) + header + payload


def tcp(sport, dport, flags):
    return struct.pack("!HHIIHHHH", sport, dport, 1000, 0, (5 << 12) | flags, 8192, 0, 0)


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_msg(name="example.com", qtype=1, response=False):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack("!HHHHHH", 0x1234, 0x8180 if response else 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", qtype, 1)


F_SYN = ipv4(6, "192.168.1.5", "93.184.216.34", tcp(51000, 443, 0x02))
F_DNS = ipv4(17, "192.168.1.5", "8.8.8.8", udp(40000, 53, dns_msg("www.example.com", 28)))
F_DNS_R = ipv4(17, "8.8.8.8", "192.168.1.5", udp(53, 40000, dns_msg(response=True)))
F_UDP = ipv4(17, "192.168.1.9", "192.168.1.10", udp(5000, 6000, b"hi"))
F_PING = ipv4(1, "192.168.1.5", "192.168.1.1", bytes([8, 0, 0, 0, 0, 1, 0, 1]))
F_ARP = ETH + struct.pack("!H", 0x0806) + struct.pack(
    "!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, bytes.fromhex("112233445566"),
    socket.inet_aton("192.168.1.5"), bytes(6), socket.inet_aton("192.168.1.1"))
ALL_FRAMES = [F_SYN, F_DNS, F_DNS_R, F_UDP, F_PING, F_ARP]


def write_pcap(path, frames, start=1_700_000_000.0):
    with PcapWriter(path) as w:
        for i, f in enumerate(frames):
            w.write(start + i, f)


# ---- decoding -------------------------------------------------------------

def test_tcp_syn_and_summary():
    pkt = parse_frame(F_SYN, 12.5)
    assert (pkt.ts, pkt.layer3, pkt.protocol) == (12.5, "IPv4", "TCP")
    assert (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port) == ("192.168.1.5", "93.184.216.34", 51000, 443)
    assert "SYN" in pkt.info and "ACK" not in pkt.info
    assert (pkt.src_mac, pkt.dst_mac) == ("11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff")
    assert "TCP" in pkt.summary() and "192.168.1.5:51000 -> 93.184.216.34:443" in pkt.summary()
    assert "SYN,ACK" in parse_frame(ipv4(6, "1.1.1.1", "2.2.2.2", tcp(80, 5555, 0x12))).info


def test_dns_query_and_response():
    q = parse_frame(F_DNS)
    assert q.protocol == "DNS" and q.dns == ("www.example.com", "AAAA", False)
    assert q.info == "DNS query AAAA www.example.com"
    r = parse_frame(F_DNS_R)
    assert r.dns == ("example.com", "A", True) and r.info.startswith("DNS response")


def test_udp_icmp_arp_ipv6_vlan():
    assert parse_frame(F_UDP).protocol == "UDP" and parse_frame(F_UDP).dns is None
    assert (parse_frame(F_PING).protocol, parse_frame(F_PING).info) == ("ICMP", "echo-request")
    arp = parse_frame(F_ARP)
    assert arp.protocol == "ARP" and arp.info == "who has 192.168.1.1? tell 192.168.1.5"
    assert (arp.src_ip, arp.dst_ip) == ("192.168.1.5", "192.168.1.1")

    src, dst = (socket.inet_pton(socket.AF_INET6, a) for a in ("2001:db8::1", "2001:db8::2"))
    body = udp(1000, 2000, b"x")
    v6 = ETH + struct.pack("!H", 0x86DD) + struct.pack("!IHBB16s16s", 6 << 28, len(body), 17, 64, src, dst) + body
    pkt = parse_frame(v6)
    assert (pkt.layer3, pkt.protocol, pkt.src_ip) == ("IPv6", "UDP", "2001:db8::1")
    assert "[2001:db8::1]:1000" in pkt.summary()

    tagged = ETH + struct.pack("!HHH", 0x8100, 5, 0x0800) + F_SYN[14:]
    assert parse_frame(tagged).protocol == "TCP"


# ---- hostile / broken input -----------------------------------------------

def test_short_frames_are_none_and_truncated_frames_never_raise():
    assert parse_frame(b"") is None and parse_frame(b"\x00" * 13) is None
    for cut in range(14, len(F_SYN) + 1):
        parse_frame(F_SYN[:cut])
    assert parse_frame(F_SYN[:34]).truncated is True


def test_random_garbage_never_raises():
    rng = random.Random(1234)
    for _ in range(3000):
        frame = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
        if len(frame) > 14 and rng.random() < 0.7:        # steer many frames into the real parsers
            frame = frame[:12] + rng.choice([b"\x08\x00", b"\x08\x06", b"\x86\xdd", b"\x81\x00"]) + frame[14:]
        pkt = parse_frame(frame)
        if pkt is not None:
            pkt.summary()


def test_malicious_dns_is_rejected_or_sanitised():
    assert parse_dns(b"\x00" * 5) is None
    pointer = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    assert parse_dns(pointer) is None
    runs_past_end = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x3f" + b"a" * 10
    assert parse_dns(runs_past_end) is None
    nasty = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x05\x1b[31m" + b"\x00" + struct.pack("!HH", 1, 1)
    assert "\x1b" not in parse_dns(nasty)[0]
    assert safe_text(b"ok\x1b[0m\x07\xff") == "ok.[0m.." and len(safe_text(b"a" * 500)) <= 81


# ---- stats and filter (the pre-existing stats.py) -------------------------

def test_make_filter():
    dns_pkt, syn = parse_frame(F_DNS), parse_frame(F_SYN)
    assert make_filter("dns")(dns_pkt) and not make_filter("dns")(syn)
    assert make_filter("udp")(dns_pkt) and not make_filter("tcp")(dns_pkt)      # DNS counts as UDP
    assert make_filter("tcp", "93.184.216.34", 443)(syn)
    assert make_filter("arp")(parse_frame(F_ARP)) and make_filter("icmp")(parse_frame(F_PING))
    assert not make_filter(host="9.9.9.9")(syn) and not make_filter(port=80)(syn)
    for bad in (dict(proto="ftp"), dict(host="not-an-ip"), dict(port=0), dict(port=70000)):
        with pytest.raises(ValueError):
            make_filter(**bad)


def test_stats_and_summary_text():
    stats = Stats()
    for f in ALL_FRAMES:
        stats.add(parse_frame(f))
    assert stats.packets == 6 and stats.protocols["DNS"] == 2
    assert stats.dns_names == {"www.example.com": 1}          # queries only, not the response
    text = format_summary(stats)
    assert "Packets: 6" in text and "www.example.com" in text and "192.168.1.5" in text
    assert format_summary(Stats()) == "No packets captured."


# ---- pcap files -----------------------------------------------------------

def test_pcap_roundtrip_and_permissions():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "x.pcap")
        write_pcap(path, ALL_FRAMES)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        got = list(read_pcap(path))
        assert [f for _, f in got] == ALL_FRAMES
        assert abs(got[0][0] - 1_700_000_000.0) < 1e-3 and abs(got[2][0] - 1_700_000_002.0) < 1e-3
        magic, vmaj, vmin, _, _, _, link = struct.unpack("<IHHiIII", open(path, "rb").read(24))
        assert (magic, vmaj, vmin, link) == (0xA1B2C3D4, 2, 4, 1)

        loose = os.path.join(d, "loose.pcap")                  # an existing world-readable file gets tightened
        open(loose, "wb").close()
        os.chmod(loose, 0o644)
        write_pcap(loose, [F_SYN])
        assert stat.S_IMODE(os.stat(loose).st_mode) == 0o600


def test_pcap_reader_variants_and_damage():
    with tempfile.TemporaryDirectory() as d:
        def make(name, data):
            p = os.path.join(d, name)
            open(p, "wb").write(data)
            return p

        frame = F_SYN
        be_head = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)       # big-endian writer
        be = make("be.pcap", be_head + struct.pack(">IIII", 100, 500000, len(frame), len(frame)) + frame)
        assert list(read_pcap(be)) == [(100.5, frame)]

        ns_head = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)       # nanosecond timestamps
        ns = make("ns.pcap", ns_head + struct.pack("<IIII", 100, 500_000_000, len(frame), len(frame)) + frame)
        assert list(read_pcap(ns)) == [(100.5, frame)]

        good = os.path.join(d, "good.pcap")
        write_pcap(good, [F_SYN, F_UDP])
        data = open(good, "rb").read()
        cut = make("cut.pcap", data[:-5])                                          # last packet cut off
        assert [f for _, f in read_pcap(cut)] == [F_SYN]

        for name, blob, word in (
            ("empty.pcap", b"", "too short"),
            ("junk.pcap", b"x" * 100, "magic"),
            ("ng.pcap", b"\x0a\x0d\x0d\x0a" + b"\x00" * 40, "pcapng"),
            ("wifi.pcap", struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105), "link type"),
            ("huge.pcap", ns_head + struct.pack("<IIII", 1, 1, 10**9, 10**9), "large"),
        ):
            with pytest.raises(ValueError) as err:
                list(read_pcap(make(name, blob)))
            assert word in str(err.value), name


def test_pcap_writer_error_is_clean():
    with pytest.raises(RuntimeError):
        PcapWriter("/nonexistent-dir/x.pcap")


# ---- the nettool sniff command, end to end --------------------------------

def test_cli_read_pcap_with_filters(capsys):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "cap.pcap")
        write_pcap(path, ALL_FRAMES)

        assert main(["sniff", "-r", path]) == 0
        out = capsys.readouterr().out
        assert out.count("B  ") >= 6 and "Packets: 6" in out and "www.example.com" in out

        assert main(["sniff", "-r", path, "--proto", "dns"]) == 0
        out = capsys.readouterr().out
        assert "Packets: 2" in out and "TCP" not in out.split("Packets:")[0]

        assert main(["sniff", "-r", path, "--host", "93.184.216.34", "--port", "443"]) == 0
        assert "Packets: 1" in capsys.readouterr().out

        assert main(["sniff", "-r", path, "-c", "2", "-q"]) == 0
        out = capsys.readouterr().out
        assert "Packets: 2" in out and "B  " not in out.split("Packets:")[0]


def test_cli_errors_are_clean(capsys):
    assert main(["sniff", "-r", "/nonexistent.pcap"]) == 2
    assert "cannot read /nonexistent.pcap" in capsys.readouterr().err
    with tempfile.TemporaryDirectory() as d:
        junk = os.path.join(d, "junk.pcap")
        open(junk, "wb").write(b"not a pcap file at all, just text" * 3)
        assert main(["sniff", "-r", junk]) == 2
        assert "pcap" in capsys.readouterr().err
        good = os.path.join(d, "g.pcap")
        write_pcap(good, [F_SYN])
        for args in (["--proto", "ftp"], ["--host", "nope"], ["--port", "99999"]):
            assert main(["sniff", "-r", good] + args) == 2
            assert "error" in capsys.readouterr().err


def test_cli_live_capture_writes_only_matching_frames_and_private_file(capsys):
    """Replace the raw socket with canned frames and check the whole -w path."""
    original = capture_mod.open_socket

    class FakeSock:
        def __init__(self):
            self.frames = list(ALL_FRAMES)

        def recvfrom(self, _n):
            if self.frames:
                return self.frames.pop(0), ("eth0", 0, 0, 1, b"")
            raise socket.timeout

        def close(self):
            pass

    capture_mod.open_socket = lambda iface: FakeSock()
    try:
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out.pcap")
            assert main(["sniff", "-i", "eth0", "-d", "0.3", "--proto", "dns", "-w", out]) == 0
            text = capsys.readouterr().out
            assert "Packets: 2" in text and "Saved to" in text
            assert [f for _, f in read_pcap(out)] == [F_DNS, F_DNS_R]       # only what matched the filter
            assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    finally:
        capture_mod.open_socket = original


def test_cli_without_privileges_gives_clean_error(capsys):
    original = capture_mod.open_socket

    def deny(_iface):
        raise CaptureError("permission denied: live capture needs sudo")

    capture_mod.open_socket = deny
    try:
        assert main(["sniff", "-d", "1"]) == 2
    finally:
        capture_mod.open_socket = original
    assert "permission denied" in capsys.readouterr().err


def test_loopback_duplicates_are_dropped_but_real_nics_keep_both_directions():
    original = capture_mod.open_socket
    outgoing, incoming = 4, 0

    class FakeSock:
        def __init__(self):
            self.queue = [(F_SYN, ("lo", 0, outgoing, 1, b"")), (F_SYN, ("lo", 0, incoming, 1, b"")),
                          (F_UDP, ("eth0", 0, outgoing, 1, b"")), (F_UDP, ("eth0", 0, incoming, 1, b""))]

        def recvfrom(self, _n):
            if self.queue:
                return self.queue.pop(0)
            raise socket.timeout

        def close(self):
            pass

    capture_mod.open_socket = lambda iface: FakeSock()
    try:
        got = list(sniff(None, duration=0.3))
    finally:
        capture_mod.open_socket = original
    assert [p.protocol for p in got] == ["TCP", "UDP", "UDP"]


# ---- real capture on the loopback interface -------------------------------

def test_live_capture_on_loopback():
    marker, got, raw = b"nettoolkit-test-marker", [], []
    # Bind a receiver so no ICMP "port unreachable" is generated (it would quote our marker again).
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    port = receiver.getsockname()[1]

    def send():
        time.sleep(0.5)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(marker, ("127.0.0.1", port))          # exactly one datagram
        s.close()

    threading.Thread(target=send, daemon=True).start()
    try:
        for pkt in sniff("lo", duration=2, on_frame=lambda ts, f: raw.append(f)):
            if pkt.dst_port == port:
                got.append(pkt)
    except CaptureError:
        return          # not root / no AF_PACKET here: covered by the fake-socket tests above
    finally:
        receiver.close()
    assert len(got) == 1, f"expected one copy of the datagram, saw {len(got)}"
    assert got[0].protocol == "UDP" and got[0].src_ip == "127.0.0.1"
    assert sum(marker in f for f in raw) == 1
