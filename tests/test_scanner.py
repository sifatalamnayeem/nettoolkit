import socket

import pytest

from nettoolkit.scanner import scan_ports
from nettoolkit.scanner.scanner import parse_ports


def test_parse_ports_mixed():
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_parse_ports_invalid():
    with pytest.raises(ValueError):
        parse_ports("0")
    with pytest.raises(ValueError):
        parse_ports("100-50")


def test_scan_finds_open_local_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    open_port = server.getsockname()[1]
    try:
        results = scan_ports("127.0.0.1", [open_port], timeout=1)
        assert [r.port for r in results] == [open_port]
        assert results[0].open is True
    finally:
        server.close()


def test_scan_closed_port_not_reported():
    # bind then close to get a port that is very likely closed
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert scan_ports("127.0.0.1", [port], timeout=0.5) == []
