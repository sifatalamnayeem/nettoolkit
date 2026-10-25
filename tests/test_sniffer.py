import os
import random
import socket
import struct
import tempfile
import threading
import time

from nettoolkit.cli import main
from nettoolkit.sniffer import parse_frame, summarize
from nettoolkit.sniffer.capture import CaptureError, PcapWriter, capture, make_filter
from nettoolkit.sniffer.packets import parse_dns_query, safe_text

ETH = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566")  # dst, src


def ipv4(proto, src, dst, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return ETH + struct.pack("!H", 0x0800) + header + payload


def tcp(sport, dport, flags):
    return struct.pack("!HHIIHHHH", sport, dport, 1000, 0, (5 << 12) | flags, 8192, 0, 0)


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name="example.com", qtype=1, response=False):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    flags = 0x8180 if response else 0x0100
    return struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", qtype, 1)


# ---- decoding -------------------------------------------------------------

def test_tcp_syn():
    pkt = parse_frame(ipv4(6, "192.168.1.5", "93.184.216.34", tcp(51000, 443, 0x02)))
    assert (pkt.layer3, pkt.protocol) == ("IPv4", "TCP")
    assert (pkt.src, pkt.dst, pkt.src_port, pkt.dst_port) == ("192.168.1.5", "93.184.216.34", 51000, 443)
    assert "SYN" in pkt.info and "ACK" not in pkt.info
    assert pkt.src_mac == "11:22:33:44:55:66" and pkt.dst_mac == "aa:bb:cc:dd:ee:ff"
    assert "192.168.1.5:51000 -> 93.184.216.34:443" in summarize(pkt)


def test_tcp_syn_ack():
    assert "SYN,ACK" in parse_frame(ipv4(6, "1.1.1.1", "2.2.2.2", tcp(80, 5555, 0x12))).info


def test_dns_query_and_response():
    q = parse_frame(ipv4(17, "192.168.1.5", "8.8.8.8", udp(40000, 53, dns_query("www.example.com", 28))))
    assert q.protocol == "DNS" and q.info == "DNS query AAAA www.example.com"
    r = parse_frame(ipv4(17, "8.8.8.8", "192.168.1.5", udp(53, 40000, dns_query(response=True))))
    assert r.info == "DNS response A example.com"


def test_plain_udp_and_icmp():
    assert parse_frame(ipv4(17, "1.1.1.1", "2.2.2.2", udp(5000, 6000, b"hi"))).protocol == "UDP"
    ping = parse_frame(ipv4(1, "1.1.1.1", "2.2.2.2", bytes([8, 0, 0, 0, 0, 1, 0, 1])))
    assert (ping.protocol, ping.info) == ("ICMP", "echo-request")


def test_arp_request():
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, bytes.fromhex("112233445566"),
                      socket.inet_aton("192.168.1.5"), bytes(6), socket.inet_aton("192.168.1.1"))
    pkt = parse_frame(ETH + struct.pack("!H", 0x0806) + arp)
    assert pkt.protocol == "ARP" and pkt.info == "who has 192.168.1.1? tell 192.168.1.5"


def test_ipv6_udp():
    src, dst = socket.inet_pton(socket.AF_INET6, "2001:db8::1"), socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    body = udp(1000, 2000, b"x")
    header = struct.pack("!IHBB16s16s", 6 << 28, len(body), 17, 64, src, dst)
    pkt = parse_frame(ETH + struct.pack("!H", 0x86DD) + header + body)
    assert (pkt.layer3, pkt.protocol, pkt.src) == ("IPv6", "UDP", "2001:db8::1")
    assert "[2001:db8::1]:1000" in summarize(pkt)


def test_vlan_tag_is_skipped():
    inner = ipv4(6, "1.1.1.1", "2.2.2.2", tcp(1, 2, 0x02))[14:]
    frame = ETH + struct.pack("!HHH", 0x8100, 5, 0x0800) + inner
    assert parse_frame(frame).protocol == "TCP"


# ---- hostile / broken input -----------------------------------------------

def test_truncated_frames_do_not_raise():
    good = ipv4(6, "1.1.1.1", "2.2.2.2", tcp(1, 2, 0x02))
    for cut in range(len(good) + 1):
        parse_frame(good[:cut])
    assert parse_frame(good[:20]).truncated is True


def test_random_garbage_never_raises():
    rng = random.Random(1234)
    for _ in range(3000):
        frame = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
        if len(frame) > 14 and rng.random() < 0.7:  # steer some into the real parsers
            frame = frame[:12] + rng.choice([b"\x08\x00", b"\x08\x06", b"\x86\xdd", b"\x81\x00"]) + frame[14:]
        summarize(parse_frame(frame))


def test_malicious_dns_names_are_rejected_or_sanitised():
    assert parse_dns_query(b"\x00" * 5) == ""
    pointer_loop = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    assert parse_dns_query(pointer_loop) == ""
    too_long = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x3f" + b"a" * 10  # label runs past the end
    assert parse_dns_query(too_long) == ""
    nasty = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x05\x1b[31m" + b"\x00" + struct.pack("!HH", 1, 1)
    assert "\x1b" not in parse_dns_query(nasty)


def test_safe_text_strips_control_characters():
    assert safe_text(b"ok\x1b[0m\x07\xff") == "ok.[0m.."
    assert len(safe_text(b"a" * 500)) <= 81


# ---- filter, pcap, live capture -------------------------------------------

def test_filter():
    pkt = parse_frame(ipv4(17, "192.168.1.5", "8.8.8.8", udp(40000, 53, dns_query())))
    assert make_filter("udp", "8.8.8.8", 53)(pkt)      # DNS counts as UDP
    assert make_filter("dns")(pkt)
    assert not make_filter("tcp")(pkt)
    assert not make_filter(host="9.9.9.9")(pkt)
    assert not make_filter(port=80)(pkt)


def test_pcap_file_format():
    frame = ipv4(6, "1.1.1.1", "2.2.2.2", tcp(1, 2, 0x02))
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "x.pcap")
        with PcapWriter(path) as w:
            w.write(frame, ts=1700000000.5)
        data = open(path, "rb").read()
    magic, vmaj, vmin, _, _, snaplen, link = struct.unpack("<IHHiIII", data[:24])
    assert (magic, vmaj, vmin, link) == (0xA1B2C3D4, 2, 4, 1)
    sec, usec, caplen, origlen = struct.unpack("<IIII", data[24:40])
    assert (sec, usec, caplen, origlen) == (1700000000, 500000, len(frame), len(frame))
    assert data[40:] == frame


def test_live_capture_on_loopback():
    port = 47333
    marker = b"nettoolkit-test"
    got = []

    def send():
        time.sleep(0.4)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(3):
            s.sendto(marker, ("127.0.0.1", port))
            time.sleep(0.1)
        s.close()

    try:
        threading.Thread(target=send, daemon=True).start()
        with tempfile.TemporaryDirectory() as d:
            pcap = os.path.join(d, "lo.pcap")
            for pkt in capture("lo", count=1, duration=5, accept=make_filter("udp", port=port), pcap_path=pcap):
                got.append(pkt)
            assert os.path.getsize(pcap) > 24 + 16
    except CaptureError:
        return  # not root / no AF_PACKET in this environment
    assert got and got[0].dst_port == port and got[0].src == "127.0.0.1"


def test_cli_without_privileges_gives_clean_error(capsys):
    import nettoolkit.sniffer.capture as cap

    original = cap.open_socket

    def deny(_iface):
        raise CaptureError("permission denied: run with sudo")

    cap.open_socket = deny
    try:
        assert main(["sniff", "-c", "1"]) == 2
    finally:
        cap.open_socket = original
    assert "permission denied" in capsys.readouterr().err
