import json
import random
import socket
import struct
import threading
from contextlib import contextmanager

import pytest

from nettoolkit.cli import main
from nettoolkit.dnstool import DNSError, compare_resolvers, default_resolver, lookup
from nettoolkit.dnstool.client import encode_name, parse_response, read_name


# ---- helpers: a fake DNS server on 127.0.0.1 ------------------------------

def rr(rtype, rdata, ttl=300, name=b"\xc0\x0c"):
    return name + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def response(query, answers=(), rcode=0, tc=False, txid=None):
    txid = struct.unpack("!H", query[:2])[0] if txid is None else txid
    flags = 0x8180 | rcode | (0x0200 if tc else 0)
    question = query[12:]
    return struct.pack("!HHHHHH", txid, flags, 1, len(answers), 0, 0) + question + b"".join(answers)


def txt(text):
    data = text.encode()
    return bytes([len(data)]) + data


@contextmanager
def fake_dns(handler, tcp_handler=None):
    """`handler(query) -> list of datagrams to send back` (may be empty)."""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(0.2)
    port = udp.getsockname()[1]
    stop = threading.Event()
    tcp = None

    def serve_udp():
        while not stop.is_set():
            try:
                data, addr = udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            for packet in handler(data):
                udp.sendto(packet, addr)

    def serve_tcp():
        while not stop.is_set():
            try:
                conn, _ = tcp.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                size = struct.unpack("!H", conn.recv(2))[0]
                query = conn.recv(size)
                reply = tcp_handler(query)
                conn.sendall(struct.pack("!H", len(reply)) + reply)

    threads = [threading.Thread(target=serve_udp, daemon=True)]
    if tcp_handler:
        tcp = socket.socket()
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("127.0.0.1", port))
        tcp.listen(1)
        tcp.settimeout(0.2)
        threads.append(threading.Thread(target=serve_tcp, daemon=True))
    for t in threads:
        t.start()
    try:
        yield port
    finally:
        stop.set()
        for t in threads:
            t.join(1)
        udp.close()
        if tcp:
            tcp.close()


# ---- lookups --------------------------------------------------------------

def test_a_aaaa_mx_txt_ns_records():
    def handler(q):
        qtype = struct.unpack("!H", q[-4:-2])[0]
        data = {
            1: rr(1, socket.inet_aton("93.184.216.34")),
            28: rr(28, socket.inet_pton(socket.AF_INET6, "2001:db8::1")),
            15: rr(15, struct.pack("!H", 10) + b"\x04mail\xc0\x0c"),
            16: rr(16, txt("v=spf1 -all")),
            2: rr(2, b"\x03ns1\xc0\x0c"),
        }[qtype]
        return [response(q, [data])]

    with fake_dns(handler) as port:
        def one(kind):
            answers, ms = lookup("example.com", kind, "127.0.0.1", port=port, timeout=2)
            assert ms >= 0
            return answers[0]

        a = one("A")
        assert (a.name, a.type, a.ttl, a.value) == ("example.com", "A", 300, "93.184.216.34")
        assert one("AAAA").value == "2001:db8::1"
        assert one("MX").value == "10 mail.example.com"
        assert one("TXT").value == "v=spf1 -all"
        assert one("NS").value == "ns1.example.com"


def test_ptr_accepts_an_ip_address():
    seen = []

    def handler(q):
        seen.append(read_name(q, 12)[0])
        return [response(q, [rr(12, b"\x04host\xc0\x0c")])]

    with fake_dns(handler) as port:
        answers, _ = lookup("192.0.2.5", "PTR", "127.0.0.1", port=port, timeout=2)
    assert seen == ["5.2.0.192.in-addr.arpa"] and answers[0].type == "PTR"


def test_nxdomain_and_servfail_are_reported():
    with fake_dns(lambda q: [response(q, rcode=3)]) as port:
        with pytest.raises(DNSError) as err:
            lookup("nope.example", "A", "127.0.0.1", port=port, timeout=2)
        assert "NXDOMAIN" in str(err.value)
    with fake_dns(lambda q: [response(q, rcode=2)]) as port:
        with pytest.raises(DNSError):
            lookup("x.example", "A", "127.0.0.1", port=port, timeout=2)


def test_timeout_when_server_is_silent():
    with fake_dns(lambda q: []) as port:
        with pytest.raises(DNSError) as err:
            lookup("example.com", "A", "127.0.0.1", port=port, timeout=0.4)
    assert "no reply" in str(err.value)


def test_reply_with_wrong_id_is_ignored():
    answer = rr(1, socket.inet_aton("6.6.6.6"))
    bad_only = lambda q: [response(q, [answer], txid=(struct.unpack("!H", q[:2])[0] + 1) % 65536)]
    with fake_dns(bad_only) as port:
        with pytest.raises(DNSError):                     # forged reply never accepted
            lookup("example.com", "A", "127.0.0.1", port=port, timeout=0.4)

    good = rr(1, socket.inet_aton("1.2.3.4"))
    forged_then_real = lambda q: [response(q, [answer], txid=(struct.unpack("!H", q[:2])[0] + 1) % 65536),
                                  response(q, [good])]
    with fake_dns(forged_then_real) as port:
        answers, _ = lookup("example.com", "A", "127.0.0.1", port=port, timeout=2)
    assert answers[0].value == "1.2.3.4"


def test_truncated_udp_reply_retries_over_tcp():
    real = rr(1, socket.inet_aton("10.1.2.3"))
    with fake_dns(lambda q: [response(q, tc=True)], tcp_handler=lambda q: response(q, [real])) as port:
        answers, _ = lookup("big.example", "A", "127.0.0.1", port=port, timeout=2)
    assert answers[0].value == "10.1.2.3"


# ---- hostile replies ------------------------------------------------------

def test_compression_pointer_loop_does_not_hang():
    loop = struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(4)
    with pytest.raises(DNSError):
        parse_response(loop, 1)


def test_oversized_lengths_are_rejected():
    msg = struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\x01a\x00" + struct.pack("!HHIH", 1, 1, 60, 500) + bytes(4)
    with pytest.raises(DNSError):
        parse_response(msg, 1)


def test_random_garbage_only_raises_dnserror():
    rng = random.Random(7)
    for _ in range(4000):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 90)))
        if len(data) >= 12 and rng.random() < 0.8:        # make some look like real replies
            data = b"\x00\x01\x81\x80" + data[4:]
        try:
            parse_response(data, 1)
        except DNSError:
            pass


def test_control_characters_in_txt_are_neutralised():
    with fake_dns(lambda q: [response(q, [rr(16, txt("hi\x1b[31m\x07there"))])]) as port:
        answers, _ = lookup("example.com", "TXT", "127.0.0.1", port=port, timeout=2)
    assert "\x1b" not in answers[0].value and "\x07" not in answers[0].value


# ---- input validation -----------------------------------------------------

def test_encode_name_rules():
    assert encode_name("a.example.com.") == b"\x01a\x07example\x03com\x00"
    assert encode_name("_dmarc.example.com") and encode_name("*.example.com")
    for bad in ("", "a" * 64 + ".com", "a..b", "x" * 300, "has space.com", "tab\t.com", "semi;colon.com", "a\x00b.com"):
        with pytest.raises(ValueError):
            encode_name(bad)


def test_bad_arguments():
    with pytest.raises(ValueError):
        lookup("example.com", "BOGUS", "127.0.0.1")
    with pytest.raises(ValueError):
        lookup("example.com", "A", "not-an-ip")


def test_default_resolver_is_an_ip():
    socket.inet_pton(socket.AF_INET6 if ":" in default_resolver() else socket.AF_INET, default_resolver())


# ---- compare and CLI ------------------------------------------------------

def test_compare_ranks_working_resolvers_first():
    good = rr(1, socket.inet_aton("1.1.1.1"))
    with fake_dns(lambda q: [response(q, [good])]) as port:
        rows = compare_resolvers("example.com", {"Local": "127.0.0.1", "Missing": "127.0.0.2"},
                                 rounds=2, timeout=0.3, port=port)
    assert rows[0]["resolver"] == "Local" and rows[0]["median_ms"] is not None
    assert rows[1]["median_ms"] is None and rows[1]["error"]


def test_cli_dns_text_json_and_errors(capsys):
    def handler(q):
        qtype = struct.unpack("!H", q[-4:-2])[0]
        if qtype == 15:
            return [response(q, rcode=3)]
        return [response(q, [rr(1, socket.inet_aton("93.184.216.34"))])]

    with fake_dns(handler) as port:
        base = ["dns", "example.com", "-s", "127.0.0.1", "--port", str(port), "--timeout", "2"]
        assert main(base) == 0
        assert "93.184.216.34" in capsys.readouterr().out

        assert main(base + ["--json"]) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["results"][0]["answers"][0]["value"] == "93.184.216.34"

        assert main(base + ["-t", "a", "-t", "mx"]) == 1          # MX fails, A still printed
        captured = capsys.readouterr()
        assert "93.184.216.34" in captured.out and "NXDOMAIN" in captured.err

        assert main(["dns", "example.com", "--compare", "--rounds", "1", "--timeout", "0.2", "--port", str(port)]) in (0, 1)
        capsys.readouterr()

    assert main(["dns", "bad name with spaces..", "-s", "127.0.0.1"]) == 2
    assert "invalid domain name" in capsys.readouterr().err
